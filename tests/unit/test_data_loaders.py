import pytest
from mcp_sentinel.rag.data_loaders import (
    OWASPTop10Loader,
    OWASPWebTop10Loader,
    OWASPAPITop10Loader,
    CWETop100Loader,
    SANSTop25Loader,
    FrameworkSecurityLoader,
    populate_knowledge_base
)
from mcp_sentinel.rag import KnowledgeBase, VectorStore

class TestDataLoaders:
    
    def test_owasp_llm_loader(self):
        items = OWASPTop10Loader.load()
        assert len(items) > 0
        assert items[0].id == "owasp_llm_01"
        assert items[0].owasp_id == "LLM01:2023"

    def test_owasp_web_loader(self):
        items = OWASPWebTop10Loader.load()
        assert len(items) > 0
        assert items[0].owasp_id == "A01:2021"

    def test_owasp_api_loader(self):
        items = OWASPAPITop10Loader.load()
        assert len(items) > 0
        assert items[0].owasp_id == "API1:2023"

    def test_cwe_loader(self):
        items = CWETop100Loader.load()
        assert len(items) > 0
        assert items[0].cwe_id == "CWE-787"

    def test_sans_loader(self):
        items = SANSTop25Loader.load()
        assert len(items) > 0
        # Check for original item
        assert any(i.id == "sans_cwe_89" for i in items)
        # Check for new items
        assert any(i.id == "sans_cwe_20" for i in items)
        assert any(i.id == "sans_cwe_125" for i in items)
        assert any(i.id == "sans_cwe_434" for i in items)
        # Check for latest additions
        assert any(i.id == "sans_cwe_78" for i in items)
        assert any(i.id == "sans_cwe_502" for i in items)
        assert any(i.id == "sans_cwe_611" for i in items)
        # Check for final additions
        assert any(i.id == "sans_cwe_798" for i in items)

    def test_framework_loader_fastapi(self):
        items = FrameworkSecurityLoader.load_fastapi()
        assert len(items) > 0
        assert items[0].framework == "fastapi"
        assert any(i.id == "fastapi_sql_injection" for i in items)
        assert any(i.id == "fastapi_mass_assignment" for i in items)

    def test_framework_loader_flask(self):
        items = FrameworkSecurityLoader.load_flask()
        assert len(items) > 0
        assert items[0].framework == "flask"
        assert any(i.id == "flask_debug_mode" for i in items)
        assert any(i.id == "flask_secret_key" for i in items)

    def test_populate_knowledge_base(self, tmp_path):
        store = VectorStore(persist_dir=str(tmp_path / "chroma"))
        kb = KnowledgeBase(store)
        
        stats = populate_knowledge_base(kb)
        
        assert stats["total"] > 0
        assert stats["owasp_top10_llm"] > 0
        assert stats["owasp_top10_web"] > 0
        assert stats["owasp_top10_api"] > 0
        assert stats["cwe_database"] > 0
        assert stats["sans_top25"] > 0
        assert stats["framework_django"] > 0
        assert stats["framework_fastapi"] > 0
        assert stats["framework_flask"] > 0
