let appConfig = {}

appConfig.port = '3000'
appConfig.env = 'dev'
appConfig.allowedOrigin= "*"
appConfig.db = {
    uri: "mongodb://127.0.0.1:27017/testDB"
}
appConfig.apiVersion = "/api/v1"

module.exports = {
    port: appConfig.port,
    env: appConfig.env,
    allowedOrigin: appConfig.allowedOrigin,
    db: appConfig.db,
    apiVersion: appConfig.apiVersion
}