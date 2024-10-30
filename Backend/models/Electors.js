const mongoose=require('mongoose');
const bcrypt=require('bcrypt');
const ElectorsSchema=new mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    age:{
        type:Number,
        required:true
    },
    email:{
        type:String
    },
    contact:{
        type:String
    },
    address:{
        type:String,
        required:true
    },
    uidaiNo:{
        type:Number,
        require:true,
        unique:true
    },
    password:{
        type:String,
        required:true
    },
    party:{
        type:String,
        required:true
    },
    votes:[
        {
            user:{
                type:mongoose.Schema.Types.ObjectId,
                ref:"User",
                required:true
            },
            votedAt:{
                type:Date,
                default:Date.now()
            }
        }
    ],
    voteCount:{
        type:Number,
        default:0
    }
});

//function of bcrypt
ElectorsSchema.pre('save',async function(next) {
    const electors=this;
    //hash the password only if it has been modified ( or is new )
    //i have not changes the password
    if(!electors.isModified('password'))
        return next();

    try{
        //hash password generation
        //it only store a salt
        const salt=await bcrypt.genSalt(10);
        //hash passward
        //it store user password and salt both
        const hashPassword=await bcrypt.hash(electors.password,salt);
        //override the plain password into a hash password
        electors.password=hashPassword;

        next();
    }catch(err){
        return next(err);
    }
})

//this function are make plain password + hash password and compre other plain password + hash password
//suppose you given a plain password , this function frist convert it into a hash password and then compare to hash password that are define in existing database collection
ElectorsSchema.methods.comparePassword=async function(electorPassword) {
    try{
        //use bcrypt to compare provider password with a hash password
        const isMatch=await bcrypt.compare(electorPassword,this.password);
        return isMatch;
    }catch(err){
        throw err;
    }
}
 

const Electors=mongoose.model("Electors",ElectorsSchema); //persson is a collection name
module.exports=Electors;