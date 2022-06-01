const express=require('express');
const app=express()
const pool=require('./db');
const bcrypt=require('bcrypt');
const cors=require('cors');
const jwt=require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const session=require('express-session');
const res = require('express/lib/response');

app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use(cors())
app.use(cookieParser());
// app.use(bodyParser.urlencoded({extended:true}));

app.use(
    session({
        key:'userId',
        secret:'nicework',
        resave:false,
        saveUninitialized:false,
        cookie:{
            expires:60*60*24,
        },
    })
);



app.post('/register',async(req,res)=>{
    try{
        const {username,password,email}=req.body
        const user= await pool.query('SELECT * FROM users WHERE username=$1',[username]);
        console.log(user)
        if(user.rowCount>0){
          throw new Error(`person with this username already exist`)
        }else{
            const useremail=await pool.query('SELECT * FROM users WHERE email=$1',
            [email])
            if(useremail.rowCount>0){
                throw new Error(' email already exist')
            }
            const hashedPassword=await bcrypt.hash(password,10);
            const NewUser=await pool.query('INSERT INTO users(username,password,email,roles) VALUES($1,$2,$3,$4) RETURNING *',
            [username,hashedPassword,email,'user']);
            console.log(NewUser.rows[0]);
            const id=user.rows[0].user_id;
            const token= jwt.sign({id},'jwtsecret',{
                expiresIn:300,
            })
            console.log(token);
            res.status(200).json({token:token,auth:true})

        }
        
    }
    catch(err){
        res.status(400).json(err.message)
    }
})
 const verifyJwt=(req,res,next)=>{
     const token=req.headers["x-access-token"];

     if(!token){
         res.send('no token is there')
     }else{
         jwt.verify(token,"jwtSecret",(err,decoded)=>{
             if(err){
                 res.json({auth:false,message:'authorization failed'})
             }else{
                 console.log('success verification');
                 req.userId=decoded.id;
                 next();
             }
         })
     }

 }

 app.post('/isAuth',verifyJwt,(req,res)=>{
     return res.json({auth:true,message:'you are authenticated'})
 })
app.post('/login',async(req,res)=>{
    try{
        let loginStatus=false
        const {username,password}=req.body;
        const user= await pool.query('SELECT * FROM users WHERE username=$1',[username]);
        console.log(user);
        if(user.rowCount===1){
            const compPass=await bcrypt.compare(password,user.rows[0].password)
            if(compPass){
                 loginStatus=true
                 req.session.user=user.rows[0];
                 const id=user.rows[0].user_id;
                 const token= jwt.sign({id},'jwtsecret',{
                     expiresIn:300,
                 })
                 console.log(token);
                 const result=user.rows[0];
                // res.json([user,loginStatus]);
                res.status(200).json({result,token:token,auth:true})
            }else{
                throw new Error('password is wrong')
            }
        //   return res.send(`person with this username already exist`)
        }else{
throw new Error('user doesnot exist please register')
        }
        
    }
    catch(err){
        res.status(400).json(err.message)
    }
})

app.listen(4000,()=>{
    console.log('listening at 4000');
});