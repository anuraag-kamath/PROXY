const mongoose = require('mongoose')


var url = process.env.LOGGER_MONGODB_URL || "mongodb://localhost:27017/uam"

mongoose.connect(url, { useNewUrlParser: true }, () => {
    console.log("Logger DB connected successfully @ ", url);
})



module.exports = {
    mongoose
} 