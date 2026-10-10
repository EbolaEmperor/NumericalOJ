"""Lean 词法门禁接受真实注释，仍拒绝占位和改变固定证明目标。"""

import pytest

from backend.oj_modules.faithsieve.lean_source import (
    LeanSourceError, contains_forbidden_lean, is_fixed_proof_appendix, lean_tokens,
    statement_prop_name,
)


NAME = "«FaithSieve_E1-O1_original»"
STATEMENT = f"def {NAME} : Prop := True\n#check {NAME}\n"


def test_nested_doc_and_line_comments_are_ignored_without_hiding_code():
    statement = f'/- def fake : Prop := False /- axiom sorry -/ -/\n{STATEMENT}'
    appended = f'/-- 说明；/- 嵌套说明 -/ 无需 sorry。 -/\n-- theorem fake : False\ntheorem FaithSieveProof : {NAME} := by\n  /- 不使用 axiom -/ trivial\n'
    assert statement_prop_name(lean_tokens(statement)) == NAME
    assert is_fixed_proof_appendix(lean_tokens(appended), NAME)
    assert not contains_forbidden_lean(lean_tokens(statement + appended))


@pytest.mark.parametrize('literal', [
    '"sorry -- /- axiom -/ admit"',
    '"a \\\"quoted\\\" sorry \\\\ -- /-"',
    'r"sorry -- /-"',
    'r##"sorry \' /- r#"inner"#"##',
    "'/'", "'\\\''", "'\\u002f'",
])
def test_literals_do_not_create_comments_or_forbidden_tokens(literal):
    source = f'theorem FaithSieveProof : {NAME} := by\n  let note := {literal}\n  trivial'
    tokens = lean_tokens(source)
    assert not contains_forbidden_lean(tokens)
    assert is_fixed_proof_appendix(tokens, NAME)
    assert any(token.kind == 'literal' and token.text == literal for token in tokens)


def test_quoted_identifier_keeps_comment_markers_and_keywords_as_its_name():
    name = '«sorry -- /- def fake : Prop := admit»'
    tokens = lean_tokens(f'def {name} : Prop := True')
    assert statement_prop_name(tokens) == name
    assert not contains_forbidden_lean(tokens)
    assert is_fixed_proof_appendix(lean_tokens(f'theorem FaithSieveProof : {name} := by trivial'), name)


@pytest.mark.parametrize('code', [
    'sorry', 'admit', 'axiom fake : False', 'Lean.sorryAx', 'Lean.mkSorry',
    'Declaration.axiomDecl', 'Lean.«sorryAx»', 'ADMIT',
    's!"ignored sorry {sorry}"', 'm!"ignored axiom {Lean.mkSorry}"',
    's!"{let note := "-- /-"; sorry}"',
    's! "{sorry}"', 'm!/- comment -/"{Lean.mkSorry}"',
    'dbg_trace "{(sorry : Nat)}"; True.intro',
    'throwError "{(sorry : Nat)}"',
])
def test_actual_forbidden_tokens_cannot_be_hidden_by_comments_qualification_or_interpolation(code):
    assert contains_forbidden_lean(lean_tokens(code))


def test_interpolated_literal_text_is_ignored_but_nested_expressions_are_scanned():
    tokens = lean_tokens('s!"sorry -- /- {s!"admit {1 + 1}"} axiom"')
    assert not contains_forbidden_lean(tokens)


@pytest.mark.parametrize('source', [
    'throwErrorAt ref "{(sorry : Nat)}"',
    'throwNamedError name "{(sorry : Nat)}"',
    'throwNamedErrorAt ref name "{(sorry : Nat)}"',
    'logNamedError name "{(sorry : Nat)}"',
    'logNamedErrorAt ref name "{(sorry : Nat)}"',
    'logNamedWarning name "{(sorry : Nat)}"',
    'logNamedWarningAt ref name "{(sorry : Nat)}"',
    'trace[my.trace] "{(sorry : Nat)}"',
])
def test_native_interpolation_with_complex_prefix_fails_closed_without_parsing_arbitrary_terms(source):
    with pytest.raises(LeanSourceError, match='复杂插值'):
        lean_tokens(source)


def test_plain_string_braces_are_not_treated_as_interpolation_and_matrix_trace_is_an_identifier():
    assert not contains_forbidden_lean(lean_tokens('let note := "{sorry} -- /-"'))
    assert not contains_forbidden_lean(lean_tokens('Lean.throwError "{sorry} -- /-"'))
    assert lean_tokens('Matrix.trace matrix')
    assert not contains_forbidden_lean(lean_tokens('dbg_trace "harmless sorry -- /- {1 + 1}"; True.intro'))


@pytest.mark.parametrize('source', ['/- open /- nested -/', '"unterminated', 'r##"unterminated"#', '«unclosed', "'x", 's!"{1"'])
def test_incomplete_lexical_constructs_fail_closed(source):
    with pytest.raises(LeanSourceError):
        lean_tokens(source)


@pytest.mark.parametrize('appended', [
    'theorem Other : {name} := by trivial',
    'theorem FaithSieveProof (h : {name}) : {name} := h',
    'theorem FaithSieveProof : True := by trivial',
    'theorem FaithSieveProof : {name} → {name} := by trivial',
    'theorem FaithSieveProof : {name} := by trivial\ndef helper := 1',
    'theorem FaithSieveProof : {name} := by trivial theorem helper : True := by trivial',
    'theorem FaithSieveProof : {name} := by trivial\nnamespace Extra',
    'theorem FaithSieveProof : {name} := by trivial\nvariable (h : False)',
    'theorem FaithSieveProof : {name} := by trivial\n#check FaithSieveProof',
    'theorem FaithSieveProof : {name} := by trivial\nset_option maxRecDepth 1000',
    'theorem FaithSieveProof : {name} := by trivial\nopen Nat',
    'theorem FaithSieveProof : {name}',
])
def test_appendix_must_only_prove_the_same_prop_without_extra_declarations_or_premises(appended):
    assert not is_fixed_proof_appendix(lean_tokens(appended.format(name=NAME)), NAME)


def test_array_literal_inside_proof_is_not_confused_with_a_top_level_query():
    appended = f'theorem FaithSieveProof : {NAME} := by\n  let values := #[1, 2]\n  trivial'
    assert is_fixed_proof_appendix(lean_tokens(appended), NAME)


@pytest.mark.parametrize('body', [
    'set_option maxRecDepth 1000 in by trivial',
    'by\n  set_option pp.universes false in trivial',
    'open Nat in by trivial',
    'by\n  let note := s!"a harmless sorry {1 + 1}"\n  trivial',
])
def test_explicit_scoped_option_open_and_interpolated_expressions_remain_inside_the_proof(body):
    tokens = lean_tokens(f'theorem FaithSieveProof : {NAME} := {body}')
    assert is_fixed_proof_appendix(tokens, NAME)
    assert not contains_forbidden_lean(tokens)


def test_prop_definition_must_be_unique_and_literals_cannot_fake_one():
    assert statement_prop_name(lean_tokens(STATEMENT + 'def other : Prop := True')) is None
    assert statement_prop_name(lean_tokens(STATEMENT + 'def note := "def fake : Prop := False"')) == NAME
