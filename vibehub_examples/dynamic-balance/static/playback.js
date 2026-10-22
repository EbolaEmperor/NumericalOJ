(() => {
  'use strict';

  const MAX_FRAMES = 5000;
  const MAX_SNAPSHOT_NODES = 150000;
  const durations = Object.freeze({ insert: 700, pop: 450, replace: 360, swap: 200, top: 500, size: 100, idle: 300 });

  function buildFrames(execution) {
    const rounds = Array.isArray(execution?.rounds) ? execution.rounds : [];
    const left = [], right = [], parked = [], output = [], log = [];
    const limit = Symbol('frame-limit');
    let nextId = 0;
    let conveyorOffset = 0;
    let snapshotNodes = 0;
    let median;
    let truncated = false;
    const clone = (items) => items.map((node) => ({ ...node }));
    const add = (round, values = {}) => {
      const nodeCount = left.length + right.length + parked.length;
      if (output.length >= MAX_FRAMES || snapshotNodes + nodeCount > MAX_SNAPSHOT_NODES) throw limit;
      snapshotNodes += nodeCount;
      output.push({
        left: clone(left), right: clone(right), parked: clone(parked),
        round, x: rounds[round]?.x, median, log: [...log], conveyorOffset,
        duration: durations.idle, motion: { kind: 'idle' }, ...values,
      });
    };
    const at = (heap, index) => heap.find((node) => node.index === index);
    const sort = (heap) => heap.sort((a, b) => a.index - b.index);

    function swap(heap, a, b, heapName, round, message) {
      const fromIndex = a.index, toIndex = b.index;
      a.index = toIndex;
      b.index = fromIndex;
      sort(heap);
      add(round, { duration: durations.swap, message,
        highlight: { heap: heapName, index: toIndex },
        motion: { kind: 'swap', heap: heapName, nodeId: a.id, otherNodeId: b.id, fromIndex, toIndex } });
    }

    function settle(heap, values, heapName, round) {
      if (!Array.isArray(values)) return;
      if (heap.length !== values.length) throw new Error('堆快照与操作记录的元素数不一致');
      const available = [...heap];
      const ordered = new Array(values.length);
      // 同值节点可能具有不同身份；先保留已经位于正确槽位的节点。
      values.forEach((value, index) => {
        const found = available.findIndex((node) => node.index === index && node.value === value);
        if (found !== -1) ordered[index] = available.splice(found, 1)[0];
      });
      values.forEach((value, index) => {
        if (ordered[index]) return;
        const found = available.findIndex((node) => node.value === value);
        if (found === -1) throw new Error('堆快照与操作记录的元素不一致');
        ordered[index] = available.splice(found, 1)[0];
      });
      const moved = ordered.some((node, index) => node.index !== index);
      ordered.forEach((node, index) => { node.index = index; });
      heap.splice(0, heap.length, ...ordered);
      if (moved) add(round, { duration: durations.swap, settled: true,
        motion: { kind: 'idle', heap: heapName }, message: `${heapName} 的节点归位。` });
    }

    try {
      add(0, { message: '准备开始：从传送带最左端取出下一个数字。' });
      for (let round = 0; round < rounds.length; round++) {
        const result = rounds[round];
        conveyorOffset = Math.max(conveyorOffset, round);
        add(round, { entering: true, message: `取出 ${result.x}，调用 step(${result.x})。` });
        for (const operation of result.operations || []) {
          const heapName = operation.heap;
          const heap = heapName === 'A' ? left : right;
          const higher = heapName === 'A' ? (a, b) => a.value > b.value : (a, b) => a.value < b.value;
          const label = `${heapName}.${operation.type}(${operation.type === 'insert' ? operation.value : ''})`;
          log.push(label);
          if (log.length > 5) log.shift();
          if (operation.type === 'insert') {
            // 优先复用从另一棵堆弹出的同值方块，再考虑本堆弹出的方块。
            let parkedIndex = parked.findIndex((node) => node.value === operation.value && node.heap !== heapName);
            if (parkedIndex === -1) parkedIndex = parked.findIndex((node) => node.value === operation.value);
            let node, from;
            if (parkedIndex !== -1) {
              const token = parked.splice(parkedIndex, 1)[0];
              node = { id: token.id, value: token.value, index: heap.length };
              from = { kind: 'parked', nodeId: token.id, heap: token.heap };
            } else {
              node = { id: `node-${++nextId}`, value: operation.value, index: heap.length };
              from = { kind: 'conveyor', round };
              conveyorOffset = Math.max(conveyorOffset, round + 1);
            }
            heap.push(node);
            add(round, { duration: durations.insert,
              message: `${label}：把 ${operation.value} 放到末尾。`,
              highlight: { heap: heapName, index: node.index },
              motion: { kind: 'insert', heap: heapName, nodeId: node.id, from, toIndex: node.index } });
            while (node.index > 0) {
              const parent = at(heap, Math.floor((node.index - 1) / 2));
              if (!higher(node, parent)) break;
              swap(heap, node, parent, heapName, round, `${heapName} 中的新节点上浮，恢复堆序。`);
            }
          } else if (operation.type === 'pop') {
            const root = at(heap, 0);
            if (!root) throw new Error('运行记录不能从空堆删除节点');
            const lastIndex = heap.length - 1;
            heap.splice(heap.indexOf(root), 1);
            parked.push({ id: root.id, value: root.value, heap: heapName });
            add(round, { duration: durations.pop, message: `${label}：移出堆顶 ${root.value}。`,
              motion: { kind: 'pop', heap: heapName, nodeId: root.id, fromIndex: 0 } });
            if (heap.length) {
              const tail = at(heap, lastIndex);
              tail.index = 0;
              sort(heap);
              add(round, { duration: durations.replace, message: `${heapName} 的末尾节点移到堆顶。`,
                highlight: { heap: heapName, index: 0 },
                motion: { kind: 'replace', heap: heapName, nodeId: tail.id, fromIndex: lastIndex, toIndex: 0 } });
              while (2 * tail.index + 1 < heap.length) {
                let child = at(heap, 2 * tail.index + 1);
                const sibling = at(heap, child.index + 1);
                if (sibling && higher(sibling, child)) child = sibling;
                if (!higher(child, tail)) break;
                swap(heap, tail, child, heapName, round, `${heapName} 的补位节点下沉，恢复堆序。`);
              }
            }
          } else if (operation.type === 'top') {
            const root = at(heap, 0);
            add(round, { duration: durations.top, message: `${label}：读到堆顶 ${operation.value}。`,
              highlight: { heap: heapName, index: 0 },
              motion: { kind: 'top', heap: heapName, nodeId: root?.id, fromIndex: 0 } });
          } else if (operation.type === 'size') {
            add(round, { duration: durations.size, message: `${label}：当前有 ${operation.value} 个元素。`,
              motion: { kind: 'idle', heap: heapName } });
          }
        }
        settle(left, result.left_heap, 'A', round);
        settle(right, result.right_heap, 'B', round);
        median = result.expected;
        conveyorOffset = Math.max(conveyorOffset, round + 1);
        const failure = result.error ? (execution.error || '程序运行异常')
          : result.returned !== result.expected ? '返回值不正确' : '堆状态未通过检查';
        add(round, { checked: true, returned: result.returned ?? '未返回', error: !result.passed,
          success: result.passed, message: result.passed
            ? `第 ${round + 1} 轮通过，返回 ${result.returned}。`
            : `第 ${round + 1} 轮停止：${failure}。应返回 ${result.expected}，${result.returned == null ? '函数未能返回。' : `实际返回 ${result.returned}。`}` });
        if (!result.passed) break;
      }
    } catch (error) {
      if (error !== limit) throw error;
      truncated = true;
    }
    const last = output[output.length - 1];
    if (truncated && last) {
      last.truncated = true;
      last.message = `操作较多，回放已截取前 ${output.length} 帧。`;
    } else if (last?.success && execution.passed === execution.total) {
      last.message = `全部 ${execution.total} 轮通过。`;
    }
    return output;
  }

  globalThis.NumOJHeapPlayback = Object.freeze({ buildFrames });
})();
