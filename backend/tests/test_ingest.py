from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.ingest.parsers import parse_content

def test_jsonl_invalid_line_continues():
    records, errors = parse_content("x.jsonl", b'{"host":"x"}\nnot-json\n', 10)
    assert len(records)==1
    assert errors
