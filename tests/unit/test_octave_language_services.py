from __future__ import annotations

from oj_modules.editor.octave import (
    OctaveTreeSitterService,
    verify_octave_language_runtime,
)


def _decode(service, source):
    legend = service.legend()
    data = service.semantic_tokens("user:1:matlab", source)["data"]
    lines = source.splitlines()
    decoded = []
    line = 0
    character = 0
    for offset in range(0, len(data), 5):
        delta_line, delta_character, length, token_index, modifiers = data[
            offset : offset + 5
        ]
        line += delta_line
        character = (
            delta_character if delta_line else character + delta_character
        )
        decoded.append(
            (
                lines[line][character : character + length],
                legend["tokenTypes"][token_index],
                modifiers,
            )
        )
    return decoded


def test_octave_tree_sitter_highlights_structure_without_execution():
    service = OctaveTreeSitterService()
    source = (
        "function y = normalize_vector(x)\n"
        "  n = norm(x);\n"
        "  y = zeros(size(x));\n"
        "end\n"
    )

    decoded = _decode(service, source)

    assert ("normalize_vector", "function", 1) in decoded
    assert ("x", "parameter", 1) in decoded
    assert ("n", "variable", 1) in decoded
    assert ("norm", "function", 0) in decoded
    assert ("zeros", "function", 0) in decoded
    assert ("size", "function", 0) in decoded


def test_octave_tree_sitter_prefers_method_over_nested_function_capture():
    service = OctaveTreeSitterService()

    decoded = _decode(service, "result = solver.solve(problem);\n")

    assert ("solve", "method", 0) in decoded
    assert ("solve", "function", 0) not in decoded
    assert ("result", "variable", 1) in decoded


def test_octave_runtime_verification_exercises_semantic_query():
    verify_octave_language_runtime()
