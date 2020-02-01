class BaseConfig:
    SERVER = "ws://localhost:5000"
    HELLO_INTERVAL = 60
    IDLE_TIME = 60
    MAX_FAILED_CONNECTIONS = 60
    PERSIST = True
    TLS_VERIFY = True
    HELP = ''
    EMAIL = 'ideasource@foxmail.com'


class DevelopmentConfig(BaseConfig):
    SERVER = "ws://localhost:5000"


class ProductionConfig(BaseConfig):
    pass


class TestConfig(BaseConfig):
    pass


settings = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestConfig
}
