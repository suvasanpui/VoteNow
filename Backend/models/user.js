const mongoose=require('mongoose');
const bcrypt=require('bcrypt');
const userSchema=new mongoose.Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String
    },
    contact:{
        type:String
    },
    uidaiNo:{
        type:Number,
        require:true,
        unique:true
    },
    address:{
        type:String,
        required:true
    },
    age:{
        type:Number,
        required:true
    },
    password:{
        type:String,
        required:true
    },
    isVoted:{
        type:Boolean,
        default:false
    },
    role:{
        type:String,
        enum:["voter","admin"],
        default:"voter"
    }
});

//function of bcrypt
userSchema.pre('save',async function(next) {
    const user=this;
    //hash the password only if it has been modified ( or is new )
    //i have not changes the password
    if(!user.isModified('password'))
        return next();

    try{
        //hash password generation
        //it only store a salt
        const salt=await bcrypt.genSalt(10);
        //hash passward
        //it store user password and salt both
        const hashPassword=await bcrypt.hash(user.password,salt);
        //override the plain password into a hash password
        user.password=hashPassword;

        next();
    }catch(err){
        return next(err);
    }
})

//this function are make plain password + hash password and compre other plain password + hash password
//suppose you given a plain password , this function frist convert it into a hash password and then compare to hash password that are define in existing database collection
userSchema.methods.comparePassword=async function(candidatePassword) {
    try{
        //use bcrypt to compare provider password with a hash password
        const isMatch=await bcrypt.compare(candidatePassword,this.password);
        return isMatch;
    }catch(err){
        throw err;
    }
}

const User=mongoose.model("User",userSchema); //persson is a collection name
module.exports=User;