
import sys, json

WINS = [(0,1,2),(3,4,5),(6,7,8),(0,3,6),(1,4,7),(2,5,8),(0,4,8),(2,4,6)]


def load_strategy(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return str(json.load(f).get("strategy", "first_empty"))
    except Exception:
        return "first_empty"


def winner_of(board):
    for a, b, c in WINS:
        if board[a] != " " and board[a] == board[b] == board[c]:
            return board[a]
    return None


def choose(board, strat):
    empties = [i for i, c in enumerate(board) if c == " "]
    if strat == "center_first" and 4 in empties:
        return 4
    return empties[0]


def play(strat_x, strat_o):
    board = [" "] * 9
    strat = {"X": strat_x, "O": strat_o}
    turn = "X"
    for _ in range(9):
        mv = choose(board, strat[turn])
        if board[mv] != " ":
            return "O" if turn == "X" else "X"
        board[mv] = turn
        w = winner_of(board)
        if w:
            return w
        turn = "O" if turn == "X" else "X"
    return "draw"


def main():
    sa = load_strategy(sys.argv[1])
    sb = load_strategy(sys.argv[2])
    g1 = play(sa, sb)
    g2 = play(sb, sa)
    a = b = 0
    if g1 == "X":
        a += 1
    elif g1 == "O":
        b += 1
    if g2 == "X":
        b += 1
    elif g2 == "O":
        a += 1
    winner = 1 if a > b else (2 if b > a else 0)
    print(json.dumps({"winner": winner, "details": {"g1": g1, "g2": g2}}))


main()
