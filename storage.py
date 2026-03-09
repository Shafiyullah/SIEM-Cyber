import logging
from typing import Any

from elasticsearch import AsyncElasticsearch, NotFoundError, helpers

from config import Config

logger = logging.getLogger(__name__)

# Index mapping – centralised here so any schema change is a single-file edit
_INDEX_MAPPING: dict = {
    "mappings": {
        "properties": {
            "timestamp":    {"type": "date"},
            "source":       {"type": "keyword"},
            "message":      {"type": "text"},
            "ip":           {"type": "ip"},
            "severity":     {"type": "keyword"},
            "anomaly_score":{"type": "float"},
            "ai_analysis":  {"type": "object", "enabled": False},
            # raw_log is stored but not indexed – saves space, enables retrieval
            "raw_log":      {"type": "text", "index": False},
        }
    }
}


class ElasticsearchStorage:
    """
    Async Elasticsearch storage backend.

    Lifecycle:
        storage = ElasticsearchStorage()
        await storage.initialize()   # creates the index if absent
        ...
        await storage.close()        # flush & close the connection pool
    """

    def __init__(self) -> None:
        scheme = "https" if Config.ES_USE_TLS else "http"
        self._es = AsyncElasticsearch(
            [f"{scheme}://{Config.ES_HOST}:{Config.ES_PORT}"],
            basic_auth=(Config.ES_USER, Config.ES_PASSWORD),
            # TLS certificate verification:
            #   True  – enforce in production (default when ES_USE_TLS=true)
            #   False – disable only for local dev clusters without valid certs
            verify_certs=Config.ES_USE_TLS,
        )
        self.index_name: str = Config.ES_INDEX_NAME

    # Lifecycle

    async def initialize(self) -> None:
        """Create the index with mappings if it does not already exist."""
        await self._create_index_if_missing()

    async def close(self) -> None:
        """Close the underlying connection pool gracefully."""
        await self._es.close()

    # Health

    async def is_connected(self) -> bool:
        """Return True if Elasticsearch responds to a ping."""
        try:
            return await self._es.ping()
        except Exception:
            logger.warning("Elasticsearch ping failed", exc_info=True)
            return False

    # Write

    async def store_log(self, log_data: dict[str, Any]) -> None:
        """Index a single log document."""
        try:
            await self._es.index(index=self.index_name, document=log_data)
        except Exception:
            logger.error("Failed to store single log", exc_info=True)

    async def store_bulk_logs(self, logs: list[dict[str, Any]]) -> None:
        """Bulk-index a list of log documents. No-ops on empty input."""
        if not logs:
            return
        actions = [{"_index": self.index_name, "_source": log} for log in logs]
        try:
            success, errors = await helpers.async_bulk(
                self._es, actions, raise_on_error=False, stats_only=False
            )
            if errors:
                logger.warning(
                    "Bulk index completed with %d error(s): %s", len(errors), errors[:3]
                )
        except Exception:
            logger.error("Bulk index operation failed", exc_info=True)

    # Read

    async def search_logs(
        self, query: dict[str, Any], size: int = 100
    ) -> list[dict[str, Any]]:
        """
        Execute an Elasticsearch query and return the matching _source documents.

        `size` is capped at Config.MAX_SEARCH_RESULTS to prevent runaway queries.
        """
        capped_size = min(size, Config.MAX_SEARCH_RESULTS)
        try:
            result = await self._es.search(
                index=self.index_name, body=query, size=capped_size
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except NotFoundError:
            logger.warning("Index '%s' not found during search", self.index_name)
            return []
        except Exception:
            logger.error("Search query failed", exc_info=True)
            return []

    # Private

    async def _create_index_if_missing(self) -> None:
        try:
            exists = await self._es.indices.exists(index=self.index_name)
            if not exists:
                await self._es.indices.create(index=self.index_name, body=_INDEX_MAPPING)
                logger.info("Created Elasticsearch index: %s", self.index_name)
            else:
                logger.debug("Index '%s' already exists; skipping creation", self.index_name)
        except Exception:
            logger.error("Failed to create index '%s'", self.index_name, exc_info=True)
