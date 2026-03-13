"""
数据库操作封装
"""

from contextlib import contextmanager
from typing import Generator, Optional, TypeVar, List

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from cve_analyzer.core.config import get_settings
from cve_analyzer.core.models import Base, CVE, Patch, PatchStatus, KconfigRule, KconfigAnalysis

T = TypeVar("T")


class Database:
    """数据库操作封装"""
    
    def __init__(self, db_path: Optional[str] = None):
        """
        初始化数据库连接
        
        Args:
            db_path: 数据库文件路径，None 则使用配置中的路径
        """
        if db_path is None:
            db_path = get_settings().database_path
        
        # SQLite 连接配置
        self.engine = create_engine(
            f"sqlite:///{db_path}",
            echo=False,  # 生产环境设为 False
            connect_args={"check_same_thread": False},
        )
        
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )
    
    def create_tables(self) -> None:
        """创建所有表"""
        Base.metadata.create_all(bind=self.engine)
    
    def drop_tables(self) -> None:
        """删除所有表 (危险操作!)"""
        Base.metadata.drop_all(bind=self.engine)
    
    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """
        获取数据库会话的上下文管理器
        
        Usage:
            with db.session() as session:
                cve = session.query(CVE).first()
        """
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def get_session(self) -> Session:
        """获取一个新会话 (需要手动管理)"""
        return self.SessionLocal()


# 全局数据库实例
_db: Optional[Database] = None


def get_db() -> Database:
    """获取全局数据库实例 (懒加载)"""
    global _db
    if _db is None:
        _db = Database()
    return _db


def reset_db() -> None:
    """重置数据库实例 (用于测试)"""
    global _db
    _db = None


# ============================================
# CVE 操作
# ============================================

class CVERepository:
    """CVE 数据访问对象"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create(self, cve: CVE) -> CVE:
        """创建 CVE"""
        self.session.add(cve)
        self.session.flush()
        return cve
    
    def get_by_id(self, cve_id: str) -> Optional[CVE]:
        """根据 ID 获取 CVE"""
        return self.session.execute(
            select(CVE).where(CVE.id == cve_id)
        ).scalar_one_or_none()
    
    def get_by_id_with_relations(self, cve_id: str) -> Optional[CVE]:
        """获取 CVE 及其所有关联数据"""
        from sqlalchemy.orm import joinedload
        
        result = self.session.execute(
            select(CVE)
            .options(
                joinedload(CVE.references),
                joinedload(CVE.affected_configs),
                joinedload(CVE.patches).joinedload(Patch.file_changes),
            )
            .where(CVE.id == cve_id)
        )
        return result.unique().scalar_one_or_none()
    
    def update(self, cve: CVE) -> CVE:
        """更新 CVE"""
        self.session.merge(cve)
        return cve
    
    def create_or_update(self, cve: CVE) -> CVE:
        """创建或更新 CVE"""
        existing = self.get_by_id(cve.id)
        if existing:
            # 更新现有记录
            cve.created_at = existing.created_at
            return self.update(cve)
        else:
            # 创建新记录
            return self.create(cve)
    
    def list_all(
        self,
        severity: Optional[str] = None,
        since: Optional[str] = None,
        keyword: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[List[CVE], int]:
        """
        列出 CVE (支持分页和筛选)
        
        Returns:
            (CVE 列表, 总数)
        """
        from sqlalchemy import func
        
        # 构建基础查询
        stmt = select(CVE)
        
        # 应用筛选
        if severity:
            stmt = stmt.where(CVE.severity == severity)
        if since:
            from datetime import datetime
            since_date = datetime.fromisoformat(since)
            stmt = stmt.where(CVE.published_date >= since_date)
        if keyword:
            stmt = stmt.where(
                CVE.description.ilike(f"%{keyword}%") | 
                CVE.id.ilike(f"%{keyword}%")
            )
        
        # 获取总数
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = self.session.execute(count_stmt).scalar_one()
        
        # 分页和排序
        stmt = stmt.order_by(CVE.published_date.desc()).offset(offset).limit(limit)
        
        result = self.session.execute(stmt)
        return list(result.scalars().all()), total


# ============================================
# 补丁操作
# ============================================

class PatchRepository:
    """补丁数据访问对象"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create(self, patch: Patch) -> Patch:
        """创建补丁"""
        self.session.add(patch)
        self.session.flush()
        return patch
    
    def get_by_id(self, patch_id: int) -> Optional[Patch]:
        """根据 ID 获取补丁"""
        return self.session.execute(
            select(Patch).where(Patch.id == patch_id)
        ).scalar_one_or_none()
    
    def get_by_commit(self, commit_hash: str) -> Optional[Patch]:
        """根据 commit hash 获取补丁"""
        return self.session.execute(
            select(Patch).where(
                (Patch.commit_hash == commit_hash) | 
                (Patch.commit_hash_short == commit_hash)
            )
        ).scalar_one_or_none()
    
    def list_by_cve(self, cve_id: str) -> List[Patch]:
        """获取 CVE 的所有补丁"""
        result = self.session.execute(
            select(Patch).where(Patch.cve_id == cve_id)
        )
        return list(result.scalars().all())


# ============================================
# 补丁状态操作
# ============================================

class PatchStatusRepository:
    """补丁状态数据访问对象"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create(self, status: PatchStatus) -> PatchStatus:
        """创建状态记录"""
        self.session.add(status)
        self.session.flush()
        return status
    
    def get_latest(self, cve_id: str, version: str) -> Optional[PatchStatus]:
        """获取最新的状态记录"""
        result = self.session.execute(
            select(PatchStatus)
            .where(
                (PatchStatus.cve_id == cve_id) & 
                (PatchStatus.target_version == version)
            )
            .order_by(PatchStatus.checked_at.desc())
        )
        return result.scalars().first()
    
    def list_by_cve(self, cve_id: str) -> List[PatchStatus]:
        """获取 CVE 的所有状态记录"""
        result = self.session.execute(
            select(PatchStatus)
            .where(PatchStatus.cve_id == cve_id)
            .order_by(PatchStatus.checked_at.desc())
        )
        return list(result.scalars().all())


# ============================================
# Kconfig 操作
# ============================================

class KconfigRepository:
    """Kconfig 数据访问对象"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def create_rule(self, rule: KconfigRule) -> KconfigRule:
        """创建规则"""
        self.session.add(rule)
        self.session.flush()
        return rule
    
    def get_rule(self, cve_id: str) -> Optional[KconfigRule]:
        """获取规则"""
        result = self.session.execute(
            select(KconfigRule)
            .where(KconfigRule.cve_id == cve_id)
            .order_by(KconfigRule.updated_at.desc())
        )
        return result.scalars().first()
    
    def create_analysis(self, analysis: KconfigAnalysis) -> KconfigAnalysis:
        """创建分析结果"""
        self.session.add(analysis)
        self.session.flush()
        return analysis
    
    def get_analysis(self, cve_id: str, version: str) -> Optional[KconfigAnalysis]:
        """获取分析结果"""
        result = self.session.execute(
            select(KconfigAnalysis)
            .where(
                (KconfigAnalysis.cve_id == cve_id) & 
                (KconfigAnalysis.kernel_version == version)
            )
            .order_by(KconfigAnalysis.analyzed_at.desc())
        )
        return result.scalars().first()
