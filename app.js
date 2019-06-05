const express= require('express')
const path = require('path')
const app = express()
const fs = require('fs')
const mongoose = require('mongoose')
const bodyParser = require('body-parser')
const http = require('http')
const appConfig = require('./appConfig/appConfig')

const logger = require('./app/libs/logger')

//middlewares
app.use(bodyParser.json(true))
app.use(bodyParser.urlencoded({extended: true}))
app.use(express.static(path.join(__dirname, 'client')));


// reading all the files from the models directory
let modelsPath = './app/models'
fs.readdirSync(modelsPath).forEach(function (file) {
    if (~file.indexOf('.js')) require(modelsPath + '/' + file)
  })// end reading files from models

// reading all the files from the routes directory
let routerPath = './app/routes'
fs.readdirSync(routerPath).forEach(function(file){
    if(~file.indexOf('.js')){
        let route = require(routerPath+'/'+file)
        route.setRouter(app)
    }
}) // end reading files from routes


/**
 * Create HTTP server.
 */

const server = http.createServer(app);
// start listening to http server
console.log(appConfig);
server.listen(appConfig.port);
server.on('error', onError);
server.on('listening', onListening);

// end server listening code


/**
 * Event listener for HTTP server "error" event.
 */

function onError(error) {
    if (error.syscall !== 'listen') {
      logger.error(error.code + ' not equal listen', 'serverOnErrorHandler', 10)
      throw error;
    }
  
  
    // handle specific listen errors with friendly messages
    switch (error.code) {
      case 'EACCES':
        logger.error(error.code + ':elavated privileges required', 'serverOnErrorHandler', 10);
        process.exit(1);
        break;
      case 'EADDRINUSE':
        logger.error(error.code + ':port is already in use.', 'serverOnErrorHandler', 10);
        process.exit(1);
        break;
      default:
        logger.error(error.code + ':some unknown error occured', 'serverOnErrorHandler', 10);
        throw error;
    }
  }
  
  /**
   * Event listener for HTTP server "listening" event.
   */
  
  function onListening() {
    
    var addr = server.address();
    var bind = typeof addr === 'string'
      ? 'pipe ' + addr
      : 'port ' + addr.port;
    ('Listening on ' + bind);
    logger.info('server listening on port' + addr.port, 'serverOnListeningHandler', 10);
    mongoose.connect(appConfig.db.uri,{useNewUrlParser: true, useFindAndModify: false});
  }

process.on('unhandledRejection', (reason, p) => {
    console.log('Unhandled Rejection at: Promise', p, 'reason:', reason);
    // application specific logging, throwing an error, or other logic here
});
  
//handling mongoose error in connection
mongoose.connection.on('error', function(err){
    console.log('Unable to connect to Database')
    console.log(err)
}) // end mongoose error handler

//handling monggose success conenction
mongoose.connection.on('open', function(err){
    if(err){
        console.log('Some Error occured in Database')
    } else {
        console.log('Database Successfully Connected')
    }
}) // end mongoose success connection

module.exports = app