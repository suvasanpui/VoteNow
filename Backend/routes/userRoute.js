const express = require("express");
const route = express.Router();
const {jwtmiddleware,generateToken}=require('./../jwt')

//import person model
const User = require("../models/user");

//post method for user registration in a person collection
route.post("/signup", async (req, res) => {
  try {
    const data = req.body;

    //check if admin already present or not
    const isAdmin=await User.findOne({role:"admin"});
    if(data.role==="admin" && isAdmin){
      return res.status(400).json({error:"Please correct your Role"});
    }
    if(data.age<18){
      return res.status(400).json({error:"age should be greater or equal to 18"});
    }

    const newUser = new User(data);
    const response = await newUser.save();
    console.log("Data insert successfully");

    //create payload for generate token
    const jwtPayload={
      id:response.id
    }
    console.log(JSON.stringify(jwtPayload))
    //parameter pass to generate token function 
    const token=generateToken(jwtPayload);
    console.log("token",token);

    res.status(200).json({response: response,token:token});
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


//post method for user login in a person collection
route.post('/login',async(req,res)=>{
  
  try{
    //extrct username and password fom request body
    const {uidaiNo,password}=req.body;
    //check username in person database
    const user=await User.findOne({uidaiNo:uidaiNo});
    if(!user || !(await user.comparePassword(password))){ //comparePassword is a function that match user with a password
      return res.status(401).json({error: "Invalid Username and Password"})
    } 

    //generate token
    const userPayload={
      id:user.id
    }
    //token generate
    const token=generateToken(userPayload);
    //return response
    res.json({token})
  }catch(err){
    console.log(err);
    res.status(500).json({error: "internal server error"})
  }

})

//profile route
route.get('/profile',jwtmiddleware,async(req,res)=>{
    try{
        const userData=req.user;
        const userID=userData.id;
        const user=await User.findById(userID);
        res.status(200).json({user});
    }catch(err){
        console.log(err);
        res.status(500).json({error:"user not found"})

    }
})


//api for update data
route.put('/profile/password', jwtmiddleware, async (req, res) => {
    try {
        const userId = req.user.id; // Extract the id from the token
        const { currentPassword, newPassword } = req.body; // Extract current and new passwords from request body

        // Check if currentPassword and newPassword are present in the request body
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Both Current and New Password is require' });
        }

        // Find the user by userID
        const user = await User.findById(userId);

        // If user does not exist or password does not match, return error
        if (!user || !(await user.comparePassword(currentPassword))) {
            return res.status(401).json({ error: 'Invalid current password' });
        }

        //check current password and new password are diffren
        if(currentPassword===newPassword){
          return res.status(401).json({error:"Current password and New Password should not same"});
        }

        // Update the user's password
        user.password = newPassword;
        await user.save();

        console.log('password updated successfully');
        res.status(200).json({message:"Update Successfully"});
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


module.exports=route;