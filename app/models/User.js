const mongoose = require('mongoose')
const Schema = mongoose.Schema

let userSchema = new Schema(
    {
        firstName: {type: String, default:' '},
        lastName: {type: String, default:' '},
        userId: {type: String, unique: true},
        mobileNumber: {type: Number,default: ' '},
        email: {type: String, unique: true},
        password: {type: String, default: ' '},
        createdOn: {type: Date, default: Date.now()},
    }
)

module.exports = mongoose.model('User', userSchema)