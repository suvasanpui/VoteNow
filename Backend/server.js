const express = require("express");
const app = express();
require('dotenv').config();
const cors=require("cors");

//import db connection
const db = require("./db");

//import port from env
const PORT=process.env.local_port || 8000

//we know that react run on 3000 port but here node run on 8000 port so this are manage cors npm package
app.use(cors());

//body parser store in req.body---this is most important parser
const bodyParser = require("body-parser");
app.use(bodyParser.json());

//middleware function
const logRequest=(req,res,next)=>{
    console.log(`[${new Date().toLocaleString()}] Request made to: ${req.originalUrl}`);
    next();
  }
  app.use(logRequest); //this middleware apply all route

//default route
app.get("/",function (req, res) {
    res.send("Welcome to our State");
});

//import router file
const userRoute = require("./routes/userRoute");
const electorsRoute=require('./routes/ElectorsRoute')


//use the router
app.use("/user",userRoute);
app.use('/electors',electorsRoute);

//listening port
app.listen(PORT, () => {
    console.log("Server Connected");
});