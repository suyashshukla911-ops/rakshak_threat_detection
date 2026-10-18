from app.ai.explainer import AIExplainer, ai_explainer

async def generate_report(incident: dict, explainer: AIExplainer | None = None, simulate_bad_ai: bool = False) -> tuple[str, dict, dict]:
    exp = explainer or ai_explainer
    return await exp.generate(incident, simulate_bad_ai=simulate_bad_ai)

