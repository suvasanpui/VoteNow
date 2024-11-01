const express = require("express");
const route = express.Router();
const User = require("./../models/user");
const { jwtmiddleware, generateToken } = require("../jwt");

//import candidate model
const Electors = require("../models/Electors");

//function to check this person is admin or not
const isAdmin = async (userId) => {
  try {
    const personRole = await User.findById(userId);
    if (personRole.role === "admin") {
      return true;
    }
  } catch (err) {
    return false;
  }
};

//Elector registration by admin in a Elector collection
route.post("/", jwtmiddleware, async (req, res) => {
  try {
    if (!(await isAdmin(req.user.id))) {
      res.status(403).json({ error: "Admin Not Found" });
    }
    const data = req.body;
    const newElectors = new Electors(data);
    const response = await newElectors.save();
    console.log(" Elector Data added successfully");

    res.status(200).json({ response: response });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

//to see all the electors
route.get('/',jwtmiddleware,async(req,res)=>{
  try{
    const allElectors=await Electors.find();
    const response=allElectors.map((data)=>{
    return{
      name:data.name,
      party:data.party,
      id:data.id
    }
  })
  return res.status(200).json({response})

  }catch(err){
    console.log(err);
    return res.status(500).json({error:"internal server error"});
  }
})

//this function are make a update electors
route.put("/update/:updateID", jwtmiddleware, async (req, res) => {
  try {
    if (!(await isAdmin(req.user.id))) {
      res.status(403).json({ error: "Admin not Found" });
    }

    const updateId = req.params.updateID;
    const updateElectors = req.body;
    const response = await Electors.findByIdAndUpdate(
      updateId,
      updateElectors,
      {
        new: true, //return the updated document
        runValidators: true, //run mongoose validation
      }
    );
    console.log("data updated successfully");
    res.status(200).json(response);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "some problem for fetch data" });
  }
});

//function is used to delete electors
route.delete("/delete/:deleteID", jwtmiddleware, async (req, res) => {
  try {
    if (!(await isAdmin(req.user.id))) {
      res.status(403).json({ error: "Admin not Found" });
    }
    const deleteID = req.params.deleteID;
    const response = await Electors.findByIdAndDelete(deleteID);
    console.log("delete successfully");
    res.status(200).json(response);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Candidate not found" });
  }
});

//function is used for voting
route.post("/votes/:electorsID", jwtmiddleware, async (req, res) => {
  const electorID = req.params.electorsID;
  const voterID = req.user.id; //id are come from jwtmiddleware
  try {
    const elector = await Electors.findById(electorID);
    const voter = await User.findById(voterID);

    //check elector id is valid or not
    if (!elector) {
      return res.status(404).json({ error: "Invalid Elector ID" });
    }

    //check voter id is valid or not
    if (!voter) {
      return res.status(404).json({ error: "Invalid Voter ID" });
    }

    //check user is admin or voter
    if (voter.role === "admin") {
      return res.status(404).json({ error: "Admin can not allow to vote" });
    }

    //check user is already voted or not
    if (voter.isVoted) {
      return res.status(404).json({ error: "Voter already give a vote" });
    }

    
    //update the electors details
    elector.votes.push({ user: voter });
    elector.voteCount++;
    await elector.save();

    //update the voter details
    voter.isVoted = true;
    await voter.save();
    res.status(200).json({message:"vote successfully"})
  } catch (err) {
    console.log(err);
    return res.status(500).json({ error: "Internaml server error" });
  }
});

//only admin can see which pary get how many number of votes  
route.get("/votes/counts", jwtmiddleware,async (req, res) => {
  const userID=req.user.id; //get id from jwtmiddleware
  const isUser=await User.findById(userID);
  if(isUser.role==="voter"){
    return res.status(404).json({error:"Invalid , Only Admin can see No. of Votes"})
  }
  try {
    const electorsResult = await Electors.find().sort({ voteCount: "desc" });
    const voteresult = electorsResult.map((data) => {
      return {
        electorsName: data.name,
        electorsParty: data.party,
        electorsCount: data.voteCount,
      };
    })
    return res.status(200).json({ voteresult });
  } catch (err) {
    console.log(err)
    return res.status(500).json({ error: "internal server error" });
  }
});

module.exports = route;
