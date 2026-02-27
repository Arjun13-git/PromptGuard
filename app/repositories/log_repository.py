from typing import Optional, Dict, Any, List
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
from app.core import config


class LogRepository:
	"""Data access layer for threat logs using Motor (async MongoDB client).

	Usage:
		repo = LogRepository(mongo_uri=settings.MONGO_URI, db_name=settings.DB_NAME)
		await repo.save_log({...})
	"""

	def __init__(self, mongo_uri: Optional[str] = None, db_name: Optional[str] = None, collection_name: str = "threat_logs"):
		self._mongo_uri = mongo_uri or config.settings.MONGO_URI
		self._db_name = db_name or config.settings.DB_NAME
		self._collection_name = collection_name
		self._client: Optional[AsyncIOMotorClient] = None
		self._db: Optional[AsyncIOMotorDatabase] = None
		self._collection: Optional[AsyncIOMotorCollection] = None

	def _ensure_client(self):
		if self._client is None:
			if not self._mongo_uri:
				raise RuntimeError("Mongo URI not configured for LogRepository")
			self._client = AsyncIOMotorClient(self._mongo_uri)
			self._db = self._client[self._db_name]
			self._collection = self._db[self._collection_name]

	async def save_log(self, log_data: Dict[str, Any]) -> str:
		"""Insert a log document asynchronously. Returns inserted_id as string."""
		try:
			self._ensure_client()
			assert self._collection is not None
			result = await self._collection.insert_one(log_data)
			return str(result.inserted_id)
		except Exception as e:
			raise

	async def get_analytics_summary(self) -> Dict[str, Any]:
		"""Return aggregate KPI data: counts per verdict and average latency."""
		try:
			self._ensure_client()
			pipeline = [
				{
					"$facet": {
						"verdict_counts": [
							{"$group": {"_id": "$verdict", "count": {"$sum": 1}}}
						],
						"avg_latency": [
							{"$group": {"_id": None, "avg_latency": {"$avg": "$latency_ms"}}}
						]
					}
				}
			]

			assert self._collection is not None
			cursor = self._collection.aggregate(pipeline)
			resp = await cursor.to_list(length=1)
			if not resp:
				return {"SAFE": 0, "SUSPICIOUS": 0, "MALICIOUS": 0, "avg_latency": 0.0}

			data = resp[0]
			counts = {doc["_id"]: doc["count"] for doc in data.get("verdict_counts", [])}
			avg_latency = (data.get("avg_latency", []) or [{"avg_latency": 0.0}])[0].get("avg_latency") or 0.0

			return {
				"SAFE": int(counts.get("SAFE", 0)),
				"SUSPICIOUS": int(counts.get("SUSPICIOUS", 0)),
				"MALICIOUS": int(counts.get("MALICIOUS", 0)),
				"avg_latency": float(avg_latency)
			}
		except Exception:
			return {"SAFE": 0, "SUSPICIOUS": 0, "MALICIOUS": 0, "avg_latency": 0.0}

	async def get_recent_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
		"""Return the most recent log documents sorted by `timestamp` descending."""
		try:
			self._ensure_client()
			assert self._collection is not None
			cursor = self._collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
			return await cursor.to_list(length=limit)
		except Exception:
			return []

	async def close(self) -> None:
		if self._client is not None:
			self._client.close()
			self._client = None


# Backwards compat - not recommended for production code but useful for quick imports
_default_repo: Optional[LogRepository] = None

def get_default_repo() -> LogRepository:
	global _default_repo
	if _default_repo is None:
		_default_repo = LogRepository(mongo_uri=config.settings.MONGO_URI, db_name=config.settings.DB_NAME)
	return _default_repo
