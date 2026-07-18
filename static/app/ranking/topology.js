(function (global) {
  'use strict';

  function numberOption(options, name, fallback) {
    var value = Number(options[name]);
    return Number.isFinite(value) ? value : fallback;
  }

  function create(options) {
    options = options || {};
    var nodeWidth = numberOption(options, 'nodeWidth', 176);
    var nodeHeight = numberOption(options, 'nodeHeight', 96);
    var marginX = numberOption(options, 'marginX', 24);
    var marginY = numberOption(options, 'marginY', 20);
    var columnGap = numberOption(options, 'columnGap', 88);
    var rowGap = numberOption(options, 'rowGap', 72);
    var slotPadding = numberOption(options, 'slotPadding', 46);
    var maxSlotStep = numberOption(options, 'maxSlotStep', 18);

    function edgeKey(from, to) {
      return from + ':' + to;
    }

    function layout(rules) {
      var byId = {};
      var indegree = {};
      var adjacency = {};
      rules.forEach(function (rule) {
        byId[rule.rule_id] = rule;
        indegree[rule.rule_id] = 0;
        adjacency[rule.rule_id] = [];
      });
      rules.forEach(function (rule) {
        (rule.dependencies || []).forEach(function (dependency) {
          if (adjacency[dependency]) {
            adjacency[dependency].push(rule.rule_id);
            indegree[rule.rule_id] += 1;
          }
        });
      });

      var queue = Object.keys(indegree).map(Number).filter(function (id) {
        return indegree[id] === 0;
      }).sort(function (left, right) {
        return left - right;
      });
      var order = [];
      var level = {};
      rules.forEach(function (rule) { level[rule.rule_id] = 0; });
      while (queue.length) {
        var id = queue.shift();
        order.push(id);
        (adjacency[id] || []).sort(function (left, right) {
          return left - right;
        }).forEach(function (nextId) {
          level[nextId] = Math.max(level[nextId], level[id] + 1);
          indegree[nextId] -= 1;
          if (indegree[nextId] === 0) {
            queue.push(nextId);
            queue.sort(function (left, right) { return left - right; });
          }
        });
      }
      if (order.length !== rules.length) return null;

      var columns = {};
      var maxLevel = 0;
      var maxRows = 1;
      order.forEach(function (id) {
        var currentLevel = level[id] || 0;
        maxLevel = Math.max(maxLevel, currentLevel);
        if (!columns[currentLevel]) columns[currentLevel] = [];
        columns[currentLevel].push(id);
      });

      var positions = {};
      var rowById = {};
      Object.keys(columns).map(Number).sort(function (left, right) {
        return left - right;
      }).forEach(function (currentLevel) {
        columns[currentLevel].sort(function (left, right) {
          if (currentLevel === 0) return left - right;
          function weight(id) {
            var dependencies = ((byId[id] && byId[id].dependencies) || []).filter(function (dependency) {
              return rowById[dependency] != null;
            });
            if (!dependencies.length) return Number.MAX_SAFE_INTEGER;
            return dependencies.reduce(function (sum, dependency) {
              return sum + rowById[dependency];
            }, 0) / dependencies.length;
          }
          return (weight(left) - weight(right)) || (left - right);
        });
        maxRows = Math.max(maxRows, columns[currentLevel].length);
        columns[currentLevel].forEach(function (id, row) {
          rowById[id] = row;
          positions[id] = {
            x: marginX + row * (nodeWidth + columnGap),
            y: marginY + currentLevel * (nodeHeight + rowGap)
          };
        });
      });

      return {
        positions: positions,
        width: marginX * 2 + maxRows * nodeWidth + (maxRows - 1) * columnGap,
        height: marginY * 2 + (maxLevel + 1) * nodeHeight + maxLevel * rowGap
      };
    }

    function slotOffset(index, count) {
      if (count <= 1) return 0;
      var span = Math.max(0, nodeWidth - slotPadding);
      var step = Math.min(maxSlotStep, span / Math.max(1, count - 1));
      return (index - (count - 1) / 2) * step;
    }

    function buildRoutes(edges, graphLayout) {
      var items = [];
      var bySource = {};
      var byTarget = {};
      var byBand = {};
      var routes = {};

      edges.forEach(function (edge) {
        var from = graphLayout.positions[edge.from];
        var to = graphLayout.positions[edge.to];
        if (!from || !to) return;
        var item = {fromId: edge.from, toId: edge.to, from: from, to: to};
        items.push(item);
        (bySource[edge.from] = bySource[edge.from] || []).push(item);
        (byTarget[edge.to] = byTarget[edge.to] || []).push(item);
        var band = Math.round(from.y + nodeHeight) + ':' + Math.round(to.y);
        (byBand[band] = byBand[band] || []).push(item);
      });

      Object.keys(bySource).forEach(function (key) {
        var group = bySource[key].sort(function (left, right) {
          return (left.to.x - right.to.x) || (left.toId - right.toId);
        });
        group.forEach(function (item, index) {
          item.sourceOffset = slotOffset(index, group.length);
        });
      });
      Object.keys(byTarget).forEach(function (key) {
        var group = byTarget[key].sort(function (left, right) {
          return (left.from.x - right.from.x) || (left.fromId - right.fromId);
        });
        group.forEach(function (item, index) {
          item.targetOffset = slotOffset(index, group.length);
        });
      });

      Object.keys(byBand).forEach(function (key) {
        var group = byBand[key].sort(function (left, right) {
          return (left.from.x - right.from.x) ||
            (left.to.x - right.to.x) ||
            (left.fromId - right.fromId) ||
            (left.toId - right.toId);
        });
        group.forEach(function (item) {
          item.routeX1 = item.from.x + nodeWidth / 2 + (item.sourceOffset || 0);
          item.routeX2 = item.to.x + nodeWidth / 2 + (item.targetOffset || 0);
          item.routeLeft = Math.min(item.routeX1, item.routeX2);
          item.routeRight = Math.max(item.routeX1, item.routeX2);
          item.y1 = item.from.y + nodeHeight;
          item.y2 = item.to.y - 12;
          var span = Math.max(1, item.y2 - item.y1);
          item.laneTop = item.y1 + Math.max(18, Math.min(26, span * 0.30));
          item.laneBottom = item.y2 - Math.max(18, Math.min(26, span * 0.30));
          if (item.laneBottom < item.laneTop + 10) {
            item.laneTop = item.y1 + span * 0.42;
            item.laneBottom = item.y1 + span * 0.58;
          }
        });

        function between(value, start, end) {
          return value > Math.min(start, end) + 2 && value < Math.max(start, end) - 2;
        }
        function intervalOverlap(left, right, padding) {
          return left.routeLeft <= right.routeRight + padding &&
            right.routeLeft <= left.routeRight + padding;
        }
        function laneCandidates(item) {
          var center = (item.laneTop + item.laneBottom) / 2;
          var candidates = [center];
          var step = 8;
          for (var distance = step;
               center - distance >= item.laneTop || center + distance <= item.laneBottom;
               distance += step) {
            if (center - distance >= item.laneTop) candidates.push(center - distance);
            if (center + distance <= item.laneBottom) candidates.push(center + distance);
          }
          return candidates;
        }
        function crossingPenalty(item, laneY, other) {
          var score = 0;
          if (item.routeRight - item.routeLeft >= 28) {
            if (other.routeX1 > item.routeLeft + 2 && other.routeX1 < item.routeRight - 2 &&
                between(laneY, other.y1, other.laneY)) score += 1;
            if (other.routeX2 > item.routeLeft + 2 && other.routeX2 < item.routeRight - 2 &&
                between(laneY, other.laneY, other.y2)) score += 1;
          }
          if (other.routeRight - other.routeLeft >= 28) {
            if (item.routeX1 > other.routeLeft + 2 && item.routeX1 < other.routeRight - 2 &&
                between(other.laneY, item.y1, laneY)) score += 1;
            if (item.routeX2 > other.routeLeft + 2 && item.routeX2 < other.routeRight - 2 &&
                between(other.laneY, laneY, item.y2)) score += 1;
          }
          return score;
        }

        var placed = [];
        group.slice().sort(function (left, right) {
          return (right.routeRight - right.routeLeft) - (left.routeRight - left.routeLeft) ||
            (left.routeLeft - right.routeLeft);
        }).forEach(function (item) {
          var center = (item.laneTop + item.laneBottom) / 2;
          var best = center;
          var bestScore = Infinity;
          laneCandidates(item).forEach(function (laneY) {
            var score = Math.abs(laneY - center) * 0.02;
            placed.forEach(function (other) {
              if (item.routeRight - item.routeLeft >= 28 &&
                  other.routeRight - other.routeLeft >= 28 &&
                  Math.abs(other.laneY - laneY) < 5 &&
                  intervalOverlap(item, other, 14)) {
                score += 100;
              }
              score += crossingPenalty(item, laneY, other) * 16;
            });
            if (score < bestScore) {
              bestScore = score;
              best = laneY;
            }
          });
          item.laneY = best;
          placed.push(item);
        });
      });

      var plannedRoutes = [];
      function crossLayerPoints(item, x1, y1, x2, y2) {
        var stepY = nodeHeight + rowGap;
        var fromLevel = Math.round((item.from.y - marginY) / stepY);
        var toLevel = Math.round((item.to.y - marginY) / stepY);
        if (toLevel <= fromLevel + 1) return null;
        var minX = 8;
        var maxX = Math.max(minX, graphLayout.width - 8);
        function clampX(x) { return Math.max(minX, Math.min(maxX, x)); }
        function uniquePush(list, value) {
          value = Math.round(value * 10) / 10;
          if (list.indexOf(value) < 0) list.push(value);
        }
        function yCandidates(center, minY, maxY) {
          var list = [];
          [0, -8, 8, -16, 16, -24, 24].forEach(function (delta) {
            uniquePush(list, Math.max(minY, Math.min(maxY, center + delta)));
          });
          return list;
        }
        function blockedIntervals() {
          var padding = 12;
          var intervals = [];
          Object.keys(graphLayout.positions).forEach(function (id) {
            var position = graphLayout.positions[id];
            var level = Math.round((position.y - marginY) / stepY);
            if (level > fromLevel && level < toLevel) {
              intervals.push([position.x - padding, position.x + nodeWidth + padding]);
            }
          });
          intervals.sort(function (left, right) { return left[0] - right[0]; });
          var merged = [];
          intervals.forEach(function (interval) {
            var last = merged[merged.length - 1];
            if (!last || interval[0] > last[1]) merged.push([interval[0], interval[1]]);
            else last[1] = Math.max(last[1], interval[1]);
          });
          return merged;
        }
        function xCandidates(preferredX, intervals) {
          var list = [];
          [preferredX, x1, x2, minX, maxX].forEach(function (x) {
            uniquePush(list, clampX(x));
          });
          intervals.forEach(function (interval, index) {
            uniquePush(list, clampX(interval[0] - 6));
            uniquePush(list, clampX(interval[1] + 6));
            if (index < intervals.length - 1) {
              var gapLeft = interval[1] + 6;
              var gapRight = intervals[index + 1][0] - 6;
              if (gapRight >= gapLeft) uniquePush(list, clampX((gapLeft + gapRight) / 2));
            }
          });
          return list.filter(function (x) {
            return !intervals.some(function (interval) {
              return x > interval[0] && x < interval[1];
            });
          });
        }
        function routeSegments(points) {
          var segments = [];
          for (var index = 1; index < points.length; index += 1) {
            var start = points[index - 1];
            var end = points[index];
            if (Math.abs(start.x - end.x) < 0.5 && Math.abs(start.y - end.y) < 0.5) continue;
            segments.push({
              x1: start.x,
              y1: start.y,
              x2: end.x,
              y2: end.y,
              vertical: Math.abs(start.x - end.x) < Math.abs(start.y - end.y)
            });
          }
          return segments;
        }
        function routePenalty(points) {
          var score = 0;
          var current = routeSegments(points);
          plannedRoutes.forEach(function (route) {
            var otherPoints = route.points || [
              {x: route.x1, y: route.y1},
              {x: route.x1, y: route.laneY},
              {x: route.x2, y: route.laneY},
              {x: route.x2, y: route.y2}
            ];
            routeSegments(otherPoints).forEach(function (left) {
              current.forEach(function (right) {
                if (left.vertical && right.vertical) {
                  if (Math.abs(left.x1 - right.x1) < 7 &&
                      Math.max(Math.min(left.y1, left.y2), Math.min(right.y1, right.y2)) <=
                      Math.min(Math.max(left.y1, left.y2), Math.max(right.y1, right.y2)) + 10) score += 80;
                } else if (!left.vertical && !right.vertical) {
                  if (Math.abs(left.y1 - right.y1) < 7 &&
                      Math.max(Math.min(left.x1, left.x2), Math.min(right.x1, right.x2)) <=
                      Math.min(Math.max(left.x1, left.x2), Math.max(right.x1, right.x2)) + 10) score += 70;
                } else {
                  var vertical = left.vertical ? left : right;
                  var horizontal = left.vertical ? right : left;
                  if (vertical.x1 > Math.min(horizontal.x1, horizontal.x2) + 3 &&
                      vertical.x1 < Math.max(horizontal.x1, horizontal.x2) - 3 &&
                      horizontal.y1 > Math.min(vertical.y1, vertical.y2) + 3 &&
                      horizontal.y1 < Math.max(vertical.y1, vertical.y2) - 3) score += 18;
                }
              });
            });
          });
          return score;
        }

        var sourceCenterY = y1 + rowGap / 2;
        var targetCenterY = item.to.y - rowGap / 2;
        var sourceYs = yCandidates(sourceCenterY, y1 + 12, Math.min(y1 + rowGap - 10, y2 - 36));
        var targetYs = yCandidates(
          targetCenterY,
          Math.max(y1 + 36, item.to.y - rowGap + 10),
          y2 - 8
        );
        var intervals = blockedIntervals();
        var preferredX = x1 + (x2 - x1) * 0.5;
        var corridorXs = xCandidates(preferredX, intervals);
        if (!corridorXs.length) corridorXs = [clampX(preferredX), minX, maxX];
        var bestPoints = null;
        var bestScore = Infinity;
        sourceYs.forEach(function (sourceY) {
          targetYs.forEach(function (targetY) {
            corridorXs.forEach(function (corridorX) {
              var points = [
                {x: x1, y: y1},
                {x: x1, y: sourceY},
                {x: corridorX, y: sourceY},
                {x: corridorX, y: targetY},
                {x: x2, y: targetY},
                {x: x2, y: y2}
              ];
              var score = routePenalty(points) +
                Math.abs(sourceY - sourceCenterY) * 0.5 +
                Math.abs(targetY - targetCenterY) * 0.5 +
                Math.abs(corridorX - preferredX) * 0.12;
              if (score < bestScore) {
                bestScore = score;
                bestPoints = points;
              }
            });
          });
        });
        return bestPoints;
      }

      items.forEach(function (item) {
        var x1 = item.routeX1 != null ? item.routeX1 :
          item.from.x + nodeWidth / 2 + (item.sourceOffset || 0);
        var y1 = item.y1 != null ? item.y1 : item.from.y + nodeHeight;
        var x2 = item.routeX2 != null ? item.routeX2 :
          item.to.x + nodeWidth / 2 + (item.targetOffset || 0);
        var y2 = item.y2 != null ? item.y2 : item.to.y - 12;
        var span = Math.max(1, y2 - y1);
        var laneTop = y1 + Math.max(18, Math.min(26, span * 0.30));
        var laneBottom = y2 - Math.max(18, Math.min(26, span * 0.30));
        if (laneBottom < laneTop + 10) {
          laneTop = y1 + span * 0.42;
          laneBottom = y1 + span * 0.58;
        }
        var laneY = item.laneY != null ? item.laneY : (laneTop + laneBottom) / 2;
        var points = crossLayerPoints(item, x1, y1, x2, y2);
        var route = {
          x1: x1,
          y1: y1,
          x2: x2,
          y2: y2,
          laneY: laneY,
          arrowTipY: item.to.y - 2
        };
        if (points) {
          route.points = points;
          route.laneY = points[Math.max(1, points.length - 2)].y;
        }
        plannedRoutes.push(route);
        routes[edgeKey(item.fromId, item.toId)] = route;
      });
      return routes;
    }

    function roundedPolylinePath(points, radius) {
      if (!points || !points.length) return '';
      var path = 'M ' + points[0].x + ' ' + points[0].y;
      for (var index = 1; index < points.length - 1; index += 1) {
        var previous = points[index - 1];
        var current = points[index];
        var next = points[index + 1];
        var incoming = Math.hypot(current.x - previous.x, current.y - previous.y);
        var outgoing = Math.hypot(next.x - current.x, next.y - current.y);
        if (incoming < 2 || outgoing < 2) continue;
        var cornerRadius = Math.min(radius, incoming / 2, outgoing / 2);
        var inX = current.x + (previous.x - current.x) * cornerRadius / incoming;
        var inY = current.y + (previous.y - current.y) * cornerRadius / incoming;
        var outX = current.x + (next.x - current.x) * cornerRadius / outgoing;
        var outY = current.y + (next.y - current.y) * cornerRadius / outgoing;
        path += ' L ' + inX + ' ' + inY +
          ' Q ' + current.x + ' ' + current.y + ' ' + outX + ' ' + outY;
      }
      var last = points[points.length - 1];
      return path + ' L ' + last.x + ' ' + last.y;
    }

    function edgePath(route) {
      if (route.points && route.points.length > 1) {
        return roundedPolylinePath(route.points, 10);
      }
      var x1 = route.x1;
      var y1 = route.y1;
      var x2 = route.x2;
      var y2 = route.y2;
      var laneY = route.laneY;
      var difference = x2 - x1;
      if (Math.abs(difference) < 2) {
        return 'M ' + x1 + ' ' + y1 + ' L ' + x2 + ' ' + y2;
      }
      if (Math.abs(difference) < 28) {
        var soft = Math.min(18, Math.max(8, (y2 - laneY) / 2));
        return 'M ' + x1 + ' ' + y1 +
          ' L ' + x1 + ' ' + laneY +
          ' C ' + x1 + ' ' + (laneY + soft) + ', ' +
          x2 + ' ' + (laneY + soft) + ', ' +
          x2 + ' ' + (laneY + soft * 2) +
          ' L ' + x2 + ' ' + y2;
      }
      var direction = difference >= 0 ? 1 : -1;
      var radius = Math.min(
        14,
        Math.max(6, Math.abs(difference) / 2),
        Math.max(6, (y2 - laneY) / 2)
      );
      return 'M ' + x1 + ' ' + y1 +
        ' L ' + x1 + ' ' + (laneY - radius) +
        ' Q ' + x1 + ' ' + laneY + ' ' + (x1 + direction * radius) + ' ' + laneY +
        ' L ' + (x2 - direction * radius) + ' ' + laneY +
        ' Q ' + x2 + ' ' + laneY + ' ' + x2 + ' ' + (laneY + radius) +
        ' L ' + x2 + ' ' + y2;
    }

    return Object.freeze({
      layout: layout,
      buildRoutes: buildRoutes,
      edgePath: edgePath,
      edgeKey: edgeKey
    });
  }

  global.RuleTopology = Object.freeze({create: create});
})(window);
