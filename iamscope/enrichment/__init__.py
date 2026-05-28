"""IAMScope enrichment module — post-pipeline analysis and annotation."""

from iamscope.enrichment.ghostgates import enrich_scenario, enrichment_to_binding_metadata

__all__ = ["enrich_scenario", "enrichment_to_binding_metadata"]
