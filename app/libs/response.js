
let generate = (error, message, status, data) => {
    let response = {
        error: error,
        message: message,
        status: status,
        data: data
    }

    return response
} // end generate

module.exports = {
    generate: generate
}