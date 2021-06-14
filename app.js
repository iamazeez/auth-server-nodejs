const express = require('express')
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cookie = require('cookie-parser');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
const saltRounds = 12;

app.use(express.json());
app.use(cookie());
app.use(bodyParser.urlencoded({extended:true}))
app.use(cors({
    origin:["http://localhost:3000"],
    methods:["GET","POST"],
    credentials:true
}));

app.use(session({
    key:"userId",
    secret:'top-secret-key-make-it-more-secure',
    resave:false,
    saveUninitialized:false,
    cookie:{
        expires: 60 * 60 * 24
    }
}));


const DB = 'mongodb://localhost:27017/excellence-tech';

mongoose.connect(DB,{
    useNewUrlParser:true,
    useUnifiedTopology:true,
    useCreateIndex:true,
    useFindAndModify:false
}).then(() => console.log('Database connected successfully'))
.catch(e => console.log(e));

const schema = new mongoose.Schema({
    username:{
        type: String,
        required: [true, 'username is required'],
        trim: true
      },
      password:{
          type: String,
          required: [true, 'password is required'],
          trim: true
      },
});

const User = mongoose.model('User',schema);



const verifyJWT = (req,res,next) => {
    const token = req.headers["x-access-token"];
    if(!token){
        res.send("Yo, you need a token, please login ");
    }else{
        jwt.verify(token,"secretkeyhere", (err, decode) => {
          if(err){
              res.json({auth:false,message:'you faild to login'});
          }else{
              req.userId = decode.id;
              next();
          }
        });
    }

}

app.get('/isUserAuth', verifyJWT ,(req,res) => {
    res.send('You are authenticated');
});


app.post('/register',async (req,res) => {

    try{
    const {username, password} = req.body;
     bcrypt.hash(password,saltRounds, (err,hash) => {
          if(err){
              res.send(err);
          }

          const user = new User({
              username,
              password:hash
          });

          user
          .save()
          .then(result => res.send(result))
          .catch(err => res.send(err));
     });
     
    }catch (e){
        res.send(e);
    }
});

app.get('/login',(req,res) => {
    if(req.session.user){
        res.send({auth:true,user:req.session.user});
    }else{
        res.send({auth:false})
    }
});

app.post('/login',async (req,res) => {
    try{
        const user = await User.findOne({username:req.body.username});
        
        if(user){
            bcrypt.compare(req.body.password,user.password,(err,response)=>{
                if(response){
                    
                    const id = user._id;
                    const token = jwt.sign({id} , "secretkeyhere",{
                        expiresIn:500 //5 min
                    });
                    req.session.user = user;    
                    res.json({ auth:true, token, user:user});
                }else{
                    res.json({auth:false,message:"Password does not match"});
                }
            })
        }else{
            res.send({auth:false,message:"Cant find username with this name"});
        }
       }catch (e){
           res.send(e);
       }
});

app.get('/logout',(req,res) => {
     res.clearCookie("userId");
     res.send({loggedIn:false})
});




/*
app.post('/register',async (req,res) => {

    try{
    const {username, password} = req.body;
     bcrypt.hash(password,saltRounds, (err,hash) => {
          if(err){
              res.send(err);
          }

          const user = new User({
              username,
              password:hash
          });

          user
          .save()
          .then(result => res.send(result))
          .catch(err => res.send(err));
     });
     
    }catch (e){
        res.send(e);
    }
});

app.get('/login',(req,res) => {
    if(req.session.user){
        res.send({loggedIn:true,user:req.session.user});
    }else{
        res.send({loggedIn:false})
    }
});

app.post('/login',async (req,res) => {
    try{
        const user = await User.findOne({username:req.body.username});
        
        if(user){
            bcrypt.compare(req.body.password,user.password,(err,response)=>{
                if(response){
                    req.session.user = user;
                    console.log(req.session.user);
                    res.send({ loggedIn:true, user:req.session.user});
                }else{
                    res.send({message:"Password does not match"});
                }
            })
        }else{
            res.send({message:"Cant find username with this name"});
        }
       }catch (e){
           res.send(e);
       }
});

app.get('/logout',(req,res) => {
     res.clearCookie("userId");
     res.send({loggedIn:false})
});

*/
app.listen(9000,() => {
    console.log('App is running on port 9000⚡');
})

