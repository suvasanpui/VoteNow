// Using ES6 imports
//import mongoose from 'mongoose';
require('dotenv').config()

/* Using Node.js `require()`*/
const mongoose = require('mongoose');
const mongoDBURL=process.env.local_mongo_url; // hotel is a database name
// mongoDBURL=process.env.remote_mongo_url

mongoose.connect(mongoDBURL);

const db=mongoose.connection;

//add event listener
db.on("connected",()=>{
    console.log("Connection establish");
});
db.on("disconnected",()=>{
    console.log("Connection break");
});
db.on("error",()=>{
    console.log("fail to connect",err);
});

module.exports=db;