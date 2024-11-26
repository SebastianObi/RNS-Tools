from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy_utils import database_exists, create_database


def db_get_engine(host, port, user, password, database):
    url = f"postgresql://{user}:{password}@{host}:{port}/{database}"
    if not database_exists(url):
        create_database(url)
    engine = create_engine(url, pool_size=10, echo=False)
    return engine


def db_get_session(engine):
    session = sessionmaker(bind=engine)
    return session()


def db_session(host, port, user, password, database):
    from db.schema import Base

    engine = db_get_engine(host, port, user, password, database)
    Base.metadata.create_all(engine)

    return db_get_session(engine)
