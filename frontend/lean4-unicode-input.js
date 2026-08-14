import {
  AbbreviationProvider,
  AbbreviationRewriter,
  Range,
} from "@leanprover/unicode-input";

const config = {
  abbreviationCharacter: "\\",
  customTranslations: {},
  eagerReplacementEnabled: true,
};
const provider = new AbbreviationProvider(config);

export function getLean4UnicodeAbbreviations() {
  return provider.getSymbolsByAbbreviation();
}

function selectionRanges(model, editor) {
  return (editor.getSelections() || []).map((selection) => {
    const start = model.getOffsetAt(selection.getStartPosition());
    const end = model.getOffsetAt(selection.getEndPosition());
    return new Range(start, end - start);
  });
}

export function attachLean4UnicodeInput(monaco, editor) {
  if (!editor || !editor.getModel()) return null;

  let model = editor.getModel();
  let modelDisposable = null;
  let rewriter = null;

  const textSource = {
    replaceAbbreviations(changes) {
      model = editor.getModel();
      if (!model) return Promise.resolve(false);
      const edits = changes.map((change) => ({
        range: monaco.Range.fromPositions(
          model.getPositionAt(change.range.offset),
          model.getPositionAt(change.range.offset + change.range.length),
        ),
        text: change.newText,
        forceMoveMarkers: true,
      }));
      return Promise.resolve(editor.executeEdits("lean4-unicode-input", edits));
    },
    selectionMoveMode() {
      return { kind: "MoveAllSelections" };
    },
    collectSelections() {
      model = editor.getModel();
      return model ? selectionRanges(model, editor) : [];
    },
    setSelections(ranges) {
      model = editor.getModel();
      if (!model) return;
      editor.setSelections(ranges.map((range) => {
        const start = model.getPositionAt(range.offset);
        const end = model.getPositionAt(range.offset + range.length);
        return new monaco.Selection(
          start.lineNumber,
          start.column,
          end.lineNumber,
          end.column,
        );
      }));
    },
  };

  function bindModel() {
    if (modelDisposable) modelDisposable.dispose();
    model = editor.getModel();
    rewriter = new AbbreviationRewriter(config, provider, textSource);
    modelDisposable = model && model.onDidChangeContent((event) => {
      rewriter.changeInput(event.changes.map((change) => ({
        range: new Range(change.rangeOffset, change.rangeLength),
        newText: change.text,
      })));
      void rewriter.triggerAbbreviationReplacement();
    });
  }

  bindModel();
  const disposables = [
    editor.onDidChangeModel(bindModel),
    editor.onDidChangeCursorSelection(() => {
      if (rewriter) void rewriter.changeSelections(textSource.collectSelections());
    }),
    editor.onKeyDown((event) => {
      if (
        event.keyCode !== monaco.KeyCode.Tab
        || !rewriter
        || rewriter.getTrackedAbbreviations().size === 0
      ) return;
      event.preventDefault();
      event.stopPropagation();
      void rewriter.replaceAllTrackedAbbreviations();
    }),
  ];

  return {
    dispose() {
      if (modelDisposable) modelDisposable.dispose();
      disposables.forEach((disposable) => disposable.dispose());
    },
  };
}
