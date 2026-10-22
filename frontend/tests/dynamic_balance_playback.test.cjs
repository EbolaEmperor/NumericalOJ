const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.resolve(__dirname, '../../vibehub_examples/dynamic-balance/static/playback.js'), 'utf8');
const context = vm.createContext({});
vm.runInContext(source, context, { filename: 'dynamic-balance/playback.js' });
const buildFrames = execution => structuredClone(context.NumOJHeapPlayback.buildFrames(execution));
const operation = (heap, type, value) => ({ heap, type, value });
const values = nodes => nodes.map(node => node.value);
const ids = nodes => nodes.map(node => node.id);
const checked = frames => frames.filter(frame => frame.checked);
const single = (operations, left_heap, right_heap = [], extra = {}) => ({ compiled: true, passed: 0, total: 1,
  rounds: [{ x: 9, expected: 9, returned: 9, passed: false, operations, left_heap, right_heap, ...extra }] });

test('insert reaches the tail before a stable node rises by swapping positions', () => {
  const frames = buildFrames(single([operation('A', 'insert', 7), operation('A', 'insert', 9)], [9, 7]));
  const inserts = frames.filter(frame => frame.motion.kind === 'insert');
  const swap = frames.find(frame => frame.motion.kind === 'swap');
  assert.equal(inserts.length, 2);
  assert.deepEqual(values(inserts[1].left), [7, 9]);
  assert.deepEqual(inserts[1].left.map(node => node.index), [0, 1]);
  assert.deepEqual(inserts[1].motion.from, { kind: 'conveyor', round: 0 });
  assert.equal(inserts[1].duration, 700);
  assert.equal(swap.duration, 200);
  assert.deepEqual(values(swap.left), [9, 7]);
  assert.equal(swap.motion.nodeId, inserts[1].left[1].id);
  assert.equal(swap.motion.otherNodeId, inserts[1].left[0].id);
  assert.equal(swap.left[0].id, inserts[1].left[1].id);
  assert.equal(swap.left[1].id, inserts[1].left[0].id);
});

test('pop removes only the root, then tail replacement and downward swaps have separate frames', () => {
  const frames = buildFrames(single([9, 7, 4, 3].map(value => operation('A', 'insert', value))
    .concat(operation('A', 'pop', 9)), [7, 3, 4]));
  const index = frames.findIndex(frame => frame.motion.kind === 'pop');
  const before = frames[index - 1], pop = frames[index], replace = frames[index + 1], swap = frames[index + 2];
  assert.deepEqual(pop.left.map(node => node.index), [1, 2, 3], '根移出时其他节点不可提前补位');
  assert.deepEqual(values(pop.left), [7, 4, 3]);
  assert.equal(pop.duration, 450);
  assert.deepEqual(pop.parked, [{ id: before.left[0].id, value: 9, heap: 'A' }]);
  assert.equal(replace.motion.kind, 'replace');
  assert.equal(replace.duration, 360);
  assert.equal(replace.motion.fromIndex, 3);
  assert.equal(replace.motion.toIndex, 0);
  assert.equal(replace.left[0].id, before.left[3].id);
  assert.deepEqual(values(replace.left), [3, 7, 4]);
  assert.equal(swap.motion.kind, 'swap');
  assert.equal(swap.left[1].id, before.left[3].id);
  assert.deepEqual(values(swap.left), [7, 3, 4]);
});

test('min heap uses the same independent remove, replace and downward-swap stages', () => {
  const frames = buildFrames(single([2, 8, 5, 9].map(value => operation('B', 'insert', value))
    .concat(operation('B', 'pop', 2)), [], [5, 8, 9]));
  const index = frames.findIndex(frame => frame.motion.kind === 'pop');
  assert.deepEqual(frames.slice(index, index + 3).map(frame => frame.motion.kind), ['pop', 'replace', 'swap']);
  assert.deepEqual(frames[index].right.map(node => node.index), [1, 2, 3]);
  assert.deepEqual(values(frames[index + 2].right), [5, 8, 9]);
  assert.equal(frames[index + 2].motion.heap, 'B');
});

test('single-node pop leaves an empty heap and a parked token without inventing a replacement', () => {
  const frames = buildFrames(single([operation('A', 'insert', 9), operation('A', 'pop', 9)], []));
  const pop = frames.find(frame => frame.motion.kind === 'pop');
  assert.deepEqual(pop.left, []);
  assert.equal(pop.parked.length, 1);
  assert.equal(frames.some(frame => frame.motion.kind === 'replace'), false);
});

test('top deep emphasis and size reads never modify heap values or identities', () => {
  const frames = buildFrames(single([operation('A', 'insert', 9), operation('A', 'top', 9), operation('A', 'size', 1)], [9]));
  const topIndex = frames.findIndex(frame => frame.motion.kind === 'top');
  const top = frames[topIndex], size = frames[topIndex + 1];
  assert.deepEqual(top.left, frames[topIndex - 1].left);
  assert.deepEqual(size.left, top.left);
  assert.equal(top.duration, 500);
  assert.equal(top.motion.nodeId, top.left[0].id);
  assert.equal(size.duration, 100);
  assert.deepEqual(size.motion, { kind: 'idle', heap: 'A' });
});

test('duplicate values from consecutive inputs keep separate stable node identities', () => {
  const execution = { passed: 3, total: 3, rounds: [
    { x: 5, expected: 5, returned: 5, passed: true, operations: [operation('A', 'insert', 5)], left_heap: [5], right_heap: [] },
    { x: 5, expected: 5, returned: 5, passed: true, operations: [operation('B', 'insert', 5)], left_heap: [5], right_heap: [5] },
    { x: 5, expected: 5, returned: 5, passed: true, operations: [operation('A', 'insert', 5)], left_heap: [5, 5], right_heap: [5] },
  ] };
  const frames = buildFrames(execution), final = frames.at(-1);
  assert.equal(new Set(ids(final.left).concat(ids(final.right))).size, 3);
  const inserts = frames.filter(frame => frame.motion.kind === 'insert');
  assert.deepEqual(inserts.map(frame => frame.motion.from.round), [0, 1, 2]);
  assert.equal(checked(frames)[0].left[0].id, final.left[0].id);
  assert.equal(checked(frames)[1].right[0].id, final.right[0].id);
  assert.equal(final.message, '全部 3 轮通过。');
});

test('inserting x into both heaps keeps both tokens and a correct return can pass', () => {
  const frames = buildFrames(single([operation('A', 'insert', 9), operation('B', 'insert', 9)], [9], [9], { passed: true }));
  const inserts = frames.filter(frame => frame.motion.kind === 'insert');
  assert.equal(inserts.length, 2);
  assert.deepEqual(inserts.map(frame => frame.motion.from), [{ kind: 'conveyor', round: 0 }, { kind: 'conveyor', round: 0 }]);
  assert.notEqual(inserts[0].motion.nodeId, inserts[1].motion.nodeId);
  assert.deepEqual(inserts.map(frame => frame.conveyorOffset), [1, 1], '重复插入本轮 x 不能消费下一块');
  assert.equal(frames.at(-1).left.length + frames.at(-1).right.length, 2);
  assert.equal(frames.at(-1).success, true);
  assert.equal(frames.at(-1).error, false);
});

test('the conveyor advances only when a fresh block enters and transfers do not consume the next input', () => {
  const frames = buildFrames({ passed: 2, total: 2, rounds: [
    { x: 7, expected: 7, returned: 7, passed: true,
      operations: [operation('A', 'size', 0), operation('A', 'insert', 7)], left_heap: [7], right_heap: [] },
    { x: 3, expected: 5, returned: 5, passed: true,
      operations: [operation('A', 'pop', 7), operation('B', 'insert', 7), operation('A', 'insert', 3)], left_heap: [3], right_heap: [7] },
  ] });
  assert.equal(frames[0].conveyorOffset, 0);
  assert.equal(frames.find(frame => frame.duration === 100).conveyorOffset, 0);
  assert.equal(frames.find(frame => frame.entering && frame.round === 1).conveyorOffset, 1);
  const transfer = frames.find(frame => frame.motion.kind === 'insert' && frame.motion.from.kind === 'parked');
  assert.equal(transfer.conveyorOffset, 1);
  const fresh = frames.filter(frame => frame.motion.kind === 'insert' && frame.motion.from.kind === 'conveyor');
  assert.deepEqual(fresh.map(frame => frame.conveyorOffset), [1, 2]);
  assert.deepEqual(fresh.map(frame => frame.motion.from.round), [0, 1]);
  assert.equal(frames.at(-1).conveyorOffset, 2);
  assert.ok(frames.every((frame, index) => !index || frame.conveyorOffset >= frames[index - 1].conveyorOffset));
});

test('a round which never inserts its input still advances the conveyor once on checking', () => {
  const frames = buildFrames(single([operation('A', 'size', 0)], [], [], { x: 9, expected: 9, returned: 0 }));
  assert.equal(frames.find(frame => frame.duration === 100).conveyorOffset, 0);
  assert.equal(frames.at(-1).checked, true);
  assert.equal(frames.at(-1).conveyorOffset, 1);
});

test('the same node travels between heaps through parked state instead of changing identity', () => {
  const frames = buildFrames({ passed: 3, total: 3, rounds: [
    { x: 7, expected: 7, returned: 7, passed: true, operations: [operation('A', 'insert', 7)], left_heap: [7], right_heap: [] },
    { x: 3, expected: 5, returned: 5, passed: true, operations: [operation('A', 'insert', 3), operation('A', 'pop', 7), operation('B', 'insert', 7)], left_heap: [3], right_heap: [7] },
    { x: 10, expected: 7, returned: 7, passed: true, operations: [operation('B', 'insert', 10), operation('B', 'pop', 7), operation('A', 'insert', 7)], left_heap: [7, 3], right_heap: [10] },
  ] });
  const original = checked(frames)[0].left[0].id;
  const transfers = frames.filter(frame => frame.motion.kind === 'insert' && frame.motion.from.kind === 'parked');
  assert.equal(transfers.length, 2);
  assert.deepEqual(transfers.map(frame => frame.motion.nodeId), [original, original]);
  assert.deepEqual(transfers.map(frame => frame.motion.from), [{ kind: 'parked', nodeId: original, heap: 'A' }, { kind: 'parked', nodeId: original, heap: 'B' }]);
  assert.equal(checked(frames)[1].right[0].id, original);
  assert.equal(checked(frames)[2].left[0].id, original);
  assert.deepEqual(frames.at(-1).parked, []);
});

test('duplicate parked values prefer a cross-heap transfer without collapsing the other token', () => {
  const frames = buildFrames(single([operation('A', 'insert', 5), operation('B', 'insert', 5),
    operation('A', 'pop', 5), operation('B', 'pop', 5), operation('A', 'insert', 5)], [5]));
  const inserts = frames.filter(frame => frame.motion.kind === 'insert');
  assert.equal(inserts[2].motion.nodeId, inserts[1].motion.nodeId);
  assert.equal(inserts[2].motion.from.heap, 'B');
  assert.deepEqual(frames.at(-1).parked.map(node => node.id), [inserts[0].motion.nodeId]);
});

test('authoritative snapshot settles by value while same-value same-slot nodes keep their identities', () => {
  const frames = buildFrames(single([9, 7, 7, 6, 5].map(value => operation('A', 'insert', value)), [9, 7, 7, 5, 6]));
  const settleIndex = frames.findIndex(frame => frame.settled);
  const before = frames[settleIndex - 1], settled = frames[settleIndex];
  assert.equal(settled.duration, 200);
  assert.deepEqual(settled.motion, { kind: 'idle', heap: 'A' });
  assert.deepEqual(values(settled.left), [9, 7, 7, 5, 6]);
  assert.deepEqual(ids(settled.left).slice(0, 3), ids(before.left).slice(0, 3));
  assert.deepEqual(new Set(ids(settled.left)), new Set(ids(before.left)));
  assert.equal(settled.left[3].id, before.left[4].id);
  assert.equal(settled.left[4].id, before.left[3].id);
});

test('frames preserve fractional medians, stop at the first failure and do not replay later rounds', () => {
  const frames = buildFrames({ passed: 1, total: 3, rounds: [
    { x: 999999999, expected: 999999999, returned: 999999999, passed: true,
      operations: [operation('A', 'insert', 999999999)], left_heap: [999999999], right_heap: [] },
    { x: 1000000000, expected: 999999999.5, returned: 999999999, passed: false,
      operations: [operation('B', 'insert', 1000000000)], left_heap: [999999999], right_heap: [1000000000] },
    { x: -123, expected: 999999999, returned: 999999999, passed: true,
      operations: [operation('A', 'insert', -123)], left_heap: [999999999, -123], right_heap: [1000000000] },
  ] });
  assert.equal(checked(frames).length, 2);
  assert.equal(frames.at(-1).median, 999999999.5);
  assert.equal(frames.at(-1).returned, 999999999);
  assert.equal(frames.at(-1).error, true);
  assert.ok(frames.every(frame => frame.round < 2));
  assert.ok(frames.at(-1).message.includes('应返回 999999999.5'));
});

test('an exception keeps the partial scene and marks the missing return value', () => {
  const frames = buildFrames({ passed: 0, total: 1, error: 'B.top()：不能读取空堆', rounds: [
    { x: -1, expected: -1, returned: null, passed: false, error: true,
      operations: [operation('A', 'insert', -1)], left_heap: [-1], right_heap: [] },
  ] });
  assert.equal(frames.at(-1).returned, '未返回');
  assert.equal(frames.at(-1).error, true);
  assert.deepEqual(values(frames.at(-1).left), [-1]);
  assert.ok(frames.at(-1).message.includes('B.top()'));
});

test('all output snapshots are independent and input execution data is not mutated', () => {
  const execution = single([operation('A', 'insert', 7), operation('A', 'insert', 9)], [9, 7]);
  const original = structuredClone(execution);
  const frames = buildFrames(execution);
  assert.deepEqual(execution, original);
  const insert = frames.find(frame => frame.motion.kind === 'insert');
  frames.at(-1).left[1].value = -100;
  frames.at(-1).log.push('changed');
  assert.equal(insert.left[0].value, 7);
  assert.ok(insert.log.every(item => item !== 'changed'));
});

test('every frame retains only the latest five operations including the current one in an independent log', () => {
  const frames = buildFrames(single([1, 2, 3, 4, 5, 6, 7].map(value => operation('A', 'insert', value)), [7, 4, 6, 1, 3, 2, 5]));
  assert.ok(frames.every(frame => frame.log.length <= 5));
  assert.equal(new Set(frames.map(frame => frame.log)).size, frames.length, '日志快照不得共用可变数组');
  for (const frame of frames.filter(frame => ['insert', 'swap'].includes(frame.motion.kind))) {
    const currentNode = frame.left.find(node => node.id === frame.motion.nodeId);
    assert.equal(frame.log.at(-1), `A.insert(${currentNode.value})`, '上浮帧也须保留触发本次动画的操作');
  }
  assert.deepEqual(frames.at(-1).log, [3, 4, 5, 6, 7].map(value => `A.insert(${value})`));
  const previousLog = [...frames.at(-2).log];
  frames.at(-1).log[0] = 'changed';
  assert.deepEqual(frames.at(-2).log, previousLog);
});

test('frame limit is strict and truncation does not claim an unplayed round passed', () => {
  const reads = Array.from({ length: 4095 }, () => operation('A', 'top', 7));
  const frames = buildFrames({ passed: 2, total: 2, rounds: [
    { x: 7, expected: 7, returned: 7, passed: true, operations: [operation('A', 'insert', 7), ...reads], left_heap: [7], right_heap: [] },
    { x: 8, expected: 7.5, returned: 7.5, passed: true, operations: [operation('B', 'insert', 8), ...reads], left_heap: [7], right_heap: [8] },
  ] });
  assert.equal(frames.length, 5000);
  assert.ok(frames.every(frame => frame.log.length <= 5));
  assert.equal(frames.at(-1).truncated, true);
  assert.equal(frames.at(-1).checked, undefined);
  assert.equal(checked(frames).length, 1);
  assert.ok(frames.at(-1).message.includes('5000'));
  assert.ok(!frames.at(-1).message.includes('全部 2 轮通过'));
});

test('dense heaps with many reads stop within the total snapshot-node budget before the frame limit', () => {
  const inserts = Array.from({ length: 512 }, () => operation('A', 'insert', 7));
  const reads = Array.from({ length: 2500 }, () => operation('A', 'top', 7));
  const frames = buildFrames(single([...inserts, ...reads], Array(512).fill(7)));
  const snapshotNodes = frames.reduce((sum, frame) => sum + frame.left.length + frame.right.length + frame.parked.length, 0);
  assert.ok(snapshotNodes <= 150000);
  assert.ok(frames.length < 5000);
  assert.ok(frames.some(frame => frame.motion.kind === 'top'), '应覆盖完成大堆插入后的连续读取');
  assert.equal(frames.at(-1).truncated, true);
  assert.ok(frames.at(-1).message.includes(`前 ${frames.length} 帧`));
  assert.equal(checked(frames).length, 0, '截断不能声称未完成的轮次已通过');
  const original = frames.find(frame => frame.motion.kind === 'insert').left[0];
  assert.ok(frames.filter(frame => frame.left.length).every(frame => frame.left[0].id === original.id));
  assert.deepEqual(ids(frames.at(-1).left), ids(frames.at(-2).left));
});
