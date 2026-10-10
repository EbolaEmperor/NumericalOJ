"""新的结果函数 schema 只传命题依赖，历史状态树协议仍显式区分。"""

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.transport import result_request_options, result_tool_options
from tests.unit.test_faithsieve_transport import thinking_endpoint


@pytest.mark.parametrize("function", [result_tool_options, result_request_options])
def test_v2_tree_tool_schema_has_statements_direct_dependencies_and_targets(function):
    endpoint = thinking_endpoint()
    options = function(endpoint, fields={"status", "artifact", "report"}, statuses={"ok", "inconclusive"},
                       artifact="faithsieve-work/tree.json", proof_graph_version=2)
    outer = options["tools"][0]["function"]["parameters"]
    assert set(outer["properties"]) == {"result", "artifacts"}
    schema = outer["properties"]["artifacts"]["properties"]["faithsieve-work/tree.json"]
    assert set(schema["required"]) == {"schema_version", "nodes", "edges", "target_ids", "ambiguities"}
    assert schema["properties"]["schema_version"]["enum"] == [2]
    node = schema["properties"]["nodes"]["items"]
    assert set(node["required"]) == {"id", "kind", "label", "statement", "source_type", "step_ids", "source_location", "source_text"}
    assert node["properties"]["statement"]["type"] == "string"
    assert set(schema["properties"]["edges"]["items"]["required"]) == {"id", "from", "to"}
    assert not set(node["properties"]) & {"conditions", "goal", "scope"}
    assert not set(options) & {"max_tokens", "max_output_tokens"}


def test_legacy_tool_schema_remains_v1_when_explicitly_selected():
    options = result_tool_options(thinking_endpoint(), fields={"status", "artifact", "report"},
                                  statuses={"ok"}, artifact="faithsieve-work/tree.json", proof_graph_version=1)
    schema = options["tools"][0]["function"]["parameters"]["properties"]["artifacts"]["properties"]["faithsieve-work/tree.json"]
    assert schema["properties"]["schema_version"]["enum"] == [1]
    assert "root_id" in schema["properties"]


def test_unknown_graph_schema_is_rejected_instead_of_falling_back_to_state_tree():
    with pytest.raises(FaithSieveProtocolError, match="版本"):
        result_tool_options(thinking_endpoint(), fields={"status", "artifact", "report"},
                            statuses={"ok"}, artifact="faithsieve-work/tree.json", proof_graph_version=4)
