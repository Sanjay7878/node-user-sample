const logger = require('pino')()
const moment = require('moment')

let captureError = (errorMessage, errorOrigin, errorlevel)=>{
    let currentTime = moment()
    let errorResponse = {
        timestamp: currentTime,
        errorMessage: errorMessage,
        errorOrigin: errorOrigin,
        errorlevel: errorlevel
    }

    logger.error(errorResponse)
    return errorResponse
} // end capture error

let captureInfo = (message, origin, importance) =>{
    let currentTime = moment()

    let infoResponse = {
        timestamp: currentTime,
        message: message,
        origin: origin,
        importance: importance
    }

    logger.info(infoResponse)
    return infoResponse
} // end capture info

module.exports = {
    error: captureError,
    info: captureInfo
}