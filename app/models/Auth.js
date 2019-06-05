const mongoose = require('mongoose')
const Schema = mongoose.Schema

const time = require('../libs/timeLib')

let auth = new Schema(
    {
        userId: {type: String},
        authToken: {type: String},
        tokenSecret: {type: String},
        tokenGeneratedOn: {type: Date, default: time.now()}
    }
)

module.exports = mongoose.model('Auth', auth)