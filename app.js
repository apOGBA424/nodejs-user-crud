require('dotenv').config();

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');




// middlewares
const app = express();
app.use(express.json());
// app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());




// variables
const port = process.env.PORT || 3000;
const jwtsecret = process.env.JWT_SECRET;


// temporal database
const usersList = []; //On production app, replace with real DB

app.listen(port, ()=>{console.log(`server running on port ${port}`)});



//            ROUTES

// get all user registered in database
app.get('/users', (req, res)=>{
    // console.table(usersList);
    res.json(usersList);
});


// create a new user
app.post('/signup', async(req, res)=>{

    try {
        // check if the user is registered already
        const alreadyUser = usersList.find((user)=>user.name === req.body.name);

        if (alreadyUser) {
            return res.status(409).json({'msg': 'User already exists'});
        }

        const user = {
            user_id : new Date().valueOf().toString(),
            name : req.body.name,
            password : await bcrypt.hash(req.body.password, 10),
        }

        usersList.push(user);
        res.status(201).send(`${user.name} created`);
            
    } catch (error) {
        console.log('error occured');
    }

});


   
// middleware to get user_id from cookie
const authorizeUser_by_ID_fromCookie = (req, res, next)=>{

    const cookie_token = req.cookies.authorization;
    

    // error after cookie duration expired
    if (!cookie_token) {
        // return res.json({error});
        return res.status(403).json({'msg': 'Access denied'});
    }

        console.log(`cookie_token--> ${cookie_token}`);
        
        const token_from_cookie = cookie_token.split(' ')[1];
        console.log(`\ntoken_from_cookie (after split(''))--> ${token_from_cookie}`);


        try {
            jwt.verify(token_from_cookie, jwtsecret, (err, decoded_payload)=>{
                
                //error for tampered cookie
                if (err) {
                    // return res.json({err}); 
                    return res.status(401).json({'err': 'token not valid'});
                }

                /* create a user variable in request-object and name it
                "req.user" then assign to it the "decode_payload" as the value*/
                req.user = decoded_payload;

                // return res.json({'req.user': req.user});

            });
        } catch (error) {
            return res.status(500).json({'err': 'server error from authz middleware'});
        }

    next();
}



// login
app.post('/users/login', async(req, res)=>{
    const userAccount = usersList.find((user)=>user.name === req.body.name);
    
    // check if user account exists
    if (userAccount == null) {
        res.status(400).send({'msg':'user not found'});
    }

    try {  
        // compare current password with hasdedPassword
        const isPasswordValid = await bcrypt.compare(req.body.password, userAccount.password);
        if (!isPasswordValid) {
            res.status(400).send({'msg':'password is incorrect'});
        }


        // if password is correct, sign jwt accessToken
        if (isPasswordValid) {

            const user = {
                id : userAccount.id,
                name : userAccount.name,
            }

            console.info(`user_id--> ${userAccount.id}`);
            console.info(`user_name--> ${userAccount.name}\n`);
            
            // generate an access accessToken
            const accessToken = jwt.sign(userAccount, jwtsecret) //jwtsecret is: 'jwt-secr3t'
            console.info(`jwtsecret--> ${jwtsecret}\n\n`);
            
           
            const authorization = `Bearer ${jwt_token}`;
            const authzHeader = req.headers['authorization'] = authorization;
            console.log(`authzHeader will save as--->  'authorization': ${authzHeader}`);

            // store the authzHeader in a cookie
            res.cookie('authorization', authzHeader , {maxAge:55000, httpOnly: true}); //55seconds

            return res.status(200).json({'msg':`${userAccount.name} log-in successful`,accessToken,jwtsecret});
            
        }else{
            res.status(400).send({'msg':'password not valid, log-in failed'});
        }
    } catch (err) {
        res.status(500).json({'msg': err.message});
    }
});



// protected routes only for authorised users
app.get('/user/protected',authorizeUser_by_ID_fromCookie ,(req, res)=>{
    // res.json({'msg':'protected-route middleware'});
});



// get one user by id
app.get('/user/:id', (req, res)=>{
    const user = usersList.find((user)=>user.user_id === req.params.id);
    if(user){
    res.status(200).json({msg: 'user found successfully',user});
    }else{
        res.status(404).send({'msg': 'user not found'});
    }
});


// update user's record (eg: password)
app.put('/user/update/:id', (req, res)=>{
    const user = usersList.find((user)=>user.user_id === req.params.id);
    if(!user){
        res.status(404).send({'msg': 'user not found'});
    }

    const hashedPassword = bcrypt.hashSync(req.body.password, 10);
    user.password = hashedPassword;

    res.status(200).json({msg: 'password updated successfully'});
});


// logout user
app.get('/user/logout/:id', (req, res)=>{
    const user = usersList.find((user)=>user.user_id === req.params.id);
    console.log(user)
    res.status(204).json({msg: 'log-out successful'});
});


// delete user
app.get('/user/delete/:id', (req, res)=>{
    const userIndex = usersList.findIndex((user)=>user.user_id === req.params.id);
    console.log(userIndex)

    if(userIndex === -1){
        res.status(404).send({'msg': 'user account not found'});
    }

    // remove user from userList
    const deletedUser = usersList.splice(userIndex, 1)[0];
    
    res.status(200).json({msg: `${deletedUser['name']} acct delete successful`});
});

