def sort_timeline(timeline: list[dict]) -> list[dict]:
    return sorted(timeline, key=lambda x: x["ts"])
