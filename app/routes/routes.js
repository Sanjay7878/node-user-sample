const appConfig = require('../../appConfig/appConfig')
const userController = require('../appController/userController')

// function to set up the routing in the application
module.exports.setRouter = (app) =>  {

    let baseUrl = `${appConfig.apiVersion}/user`

    //params: firstName, lastName, mobileNumber, email, password
    app.post(`${baseUrl}/signup`, userController.signupFunction)

    //params: email, password
    app.post(`${baseUrl}/login`, userController.loginFunction)
    
    //params: userId
    app.post(`${baseUrl}/logout`, userController.logoutFunction)

} // end set Router
