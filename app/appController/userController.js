const mongoose = require('mongoose')
const shortid = require('shortid')

/*Libraries*/
const check = require('../libs/check')
const response = require('../libs/response')
const logger = require('../libs/logger')
const validateInput = require('../libs/paramsValidationLib')
const paswwordLib = require('../libs/passwordLib')
const token = require('../libs/tokenLib')
const time = require('../libs/timeLib')

/*Models*/
const UserModel = mongoose.model('User')
const AuthModel = mongoose.model('Auth')  


let signupFunction = (req, res) =>{
    
    let validateUserInput = () =>{
        return new Promise((resolve, reject)=>{
            if(req.body.email){
                if(!validateInput.Email(req.body.email)){
                    let apiResponse = response.generate(true, "Email Address does not meet the requirements", 400, null)
                    reject(apiResponse)
                } else if(check.isEmpty(req.body.password)){
                    let apiResponse = response.generate(true, "Password parameter is missing", 400, null)
                    reject(apiResponse)
                } else {
                    resolve(req)
                }
            } else {
                logger.error('Required Parameter Field is missing', ' userController: SignupFunction. validateUserInput', 10)
                let apiResponse = response.generate(true, "Parameters are missing", 400, null)
                reject(apiResponse)
            }
        })
    } // end validate input

    let signup = () =>{
        return new Promise((resolve, reject)=>{
            UserModel.findOne({email: req.body.email})
                .exec((err, retrivedDetails)=>{
                    if(err){
                        logger.error(err.message, " userController: signupFunction, signup", 10)
                        let apiResponse = response.generate(true, `Some error occured: ${err.message}`, 500, null)
                        reject(apiResponse)
                    }else if(check.isEmpty(retrivedDetails)){

                        let newUser = new UserModel({
                            firstName: req.body.firstName,
                            lastName: req.body.lastName,
                            userId: shortid.generate(),
                            mobileNumber: req.body.mobileNumber,
                            email: req.body.email,
                            password: paswwordLib.hashPassword(req.body.password),
                            createdOn: time.now()
                        })

                        newUser.save((err, result)=>{
                            if(err){
                                logger.error(err, "userController: signupFunction, signup", 10)
                                let apiResponse = response.generate(true, "Failed to Create User", 500, null)
                                reject(apiResponse)
                            } else {
                                let newUserObj = result.toObject()
                                resolve(newUserObj)
                            }
                        })
                    } else {
                        logger.info("User Already Exists", ' userController: signupFunction, signup', 8)
                        let apiResponse = response.generate(true, "User Already Present", 403, null)
                        reject(apiResponse)
                    }
                })
        })
    } // end signup

    validateUserInput(req, res)
        .then(signup)
        .then((resolve)=>{
            delete resolve.password
            let apiResponse = response.generate(false, 'User Created Succesfully', 200, resolve)
            res.send(apiResponse)
        })
        .catch((err)=>{
            console.log(err)
            res.send(err)
        })
} // end signup Function

let loginFunction = (req, res)=>{

    let findUser = () =>{
        return new Promise((resolve, reject)=>{
            if(req.body.email){
                UserModel.findOne({email: req.body.email}, (err, userDetails)=>{
                        if(err){
                            logger.error(err.message, ' userController: loginFunction, findUser', 10)
                            let apiResponse = response.generate(true, `Failed Login due to ${err.message}`, 500, null)
                            reject(apiResponse)
                        } else if(check.isEmpty(userDetails)){
                            logger.error('No user Found', ' userController: loginFunction, findUser', 10)
                            let apiResponse = response.generate(true, "No user Details Found", 404, null)
                            reject(apiResponse)
                        } else {
                            logger.info('User Found', ' userController: loginFunction, findUser', 10)
                            resolve(userDetails)
                        }
                    })
            } else {
                logger.error("Email Address is missing", "userController: loginFunction, findUser", 10)
                let apiResponse = response.generate(true, "Email parameter is missing", 400, null)
                reject(apiResponse)
            }
        })
    } // end find user

    let validatePassword = (retrivedUserDetails) =>{
        return new Promise((resolve, reject)=>{
            paswwordLib.comparePassword(req.body.password, retrivedUserDetails.password, (err, isMatch)=>{
                if(err){
                    logger.error(err.message, ' usercontroller: loginFunction, validatePassword', 10)
                    let apiResponse = response.generate(true, 'Failed to login', 500, null)
                    reject(apiResponse)
                } else if(isMatch){
                    let retrivedUserDetailsObj = retrivedUserDetails.toObject()
                        delete retrivedUserDetailsObj.password
                        delete retrivedUserDetailsObj.__v
                        delete retrivedUserDetailsObj._id
                        delete retrivedUserDetailsObj.createdOn
                        resolve(retrivedUserDetailsObj)
                } else {
                    logger.error('Invalid Password', ' userController: loginFunction, validatePassword', 10)
                    let apiResponse = response.generate(true, "Password entered is Invalid", 403, null)
                    reject(apiResponse)
                }
            })
        })
    } // end validate password

    let generateToken = (userDetails) =>{
        return new Promise((resolve, reject)=>{
            token.generateToken(userDetails, (err, tokenDetails)=>{
                if(err){
                    logger.error(err.message, " userController: loginFunction, generateToken", 10)
                    let apiResponse = response.generate(true, "Failed to Genreate Token", 500, null)
                    reject(apiResponse)
                } else {
                    tokenDetails.userId = userDetails.userId
                    tokenDetails.userDetails = userDetails
                    resolve(tokenDetails)
                }
            })
        })
    } // end generateToken

    let saveToken = (tokenDetails) =>{
        return new Promise((resolve, reject)=>{
            AuthModel.findOne({userId: tokenDetails.userId}, (err, retrivedTokenDetails)=>{
                if(err){
                    logger.error(err.message, ' userController: loginFunction, saveToken', 10)
                    let apiResponse = response.generate(true, "Failed to save token details", 500, null)
                    reject(apiResponse)
                }else if(check.isEmpty(retrivedTokenDetails)){
                    let newAuth = new AuthModel({
                        userId: tokenDetails.userId,
                        authToken: tokenDetails.token,
                        tokenSecret: tokenDetails.tokenSecret,
                        tokenGeneratedOn: Date.now()
                    })

                    newAuth.save((err, newTokenDetails)=>{
                        if(err){
                            logger.error(err.message, " userController: loginFunction, saveToken", 10)
                            let apiResponse = response.generate(true, "Failed to Generate Token Details", 500, null)
                            reject(apiResponse)
                        } else {
                            let responseBody = {
                                authToken: newTokenDetails.authToken,
                                userDetails: tokenDetails.userDetails
                            }
                            resolve(responseBody)
                        }
                    })
                } else {
                    retrivedTokenDetails.authToken = tokenDetails.token
                    retrivedTokenDetails.tokenSecret = tokenDetails.tokenSecret
                    retrivedTokenDetails.tokenGeneratedOn = time.now()

                    retrivedTokenDetails.save((err, newTokenDetails)=>{
                        if(err){
                            logger.error(err.message, " userController: loginFunction, saveToken", 10)
                            let apiResponse = response.generate(true, "Failed to Generate Token Details", 500, null)
                            reject(apiResponse)
                        } else {
                            let responseBody = {
                                authToken: newTokenDetails.authToken,
                                userDetails: tokenDetails.userDetails
                            }
                            resolve(responseBody)
                        }
                    })
                }
            })
        })
    } // end save token

    findUser(req, res)
        .then(validatePassword)
        .then(generateToken)
        .then(saveToken)
        .then((resolve)=>{
            console.log("Login Successfully")
            let apiResponse = response.generate(false, "Login Successful", 200, resolve)
            res.status(200)
            res.send(apiResponse)
        })
        .catch((err)=>{
            console.log("Login Failed")
            console.log(err)
            res.status(err.status)
            res.send(err)
        })

} // end login function

let logoutFunction = (req, res) =>{
    AuthModel.deleteOne({userId: req.body.userId}, (err, result)=>{
        if(err){
            logger.error(err.message, ' userController: logoutFunction', 10)
            let apiResponse = response.generate(true, `Failed Logout due to ${err.message}`, 500, null)
            res.send(apiResponse)
        } else if(result.deletedCount === 0){
            logger.error('User is not logged-in', ' userController: logoutFunction', 10)
            let apiResponse = response.generate(true, "User is not logged-in", 404, null)
            res.send(apiResponse)
        } else {
            let apiResponse = response.generate(false, "Logged out successfully", 200, null)
            res.send(apiResponse)
        }
    })
} // end logout function


module.exports = {
    signupFunction: signupFunction,
    loginFunction: loginFunction,
    logoutFunction: logoutFunction
}