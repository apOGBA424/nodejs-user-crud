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



//-----------------------------ROUTES-----------------------------

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
        console.log(`from Log-in, userAccount.password---> ${userAccount.password}`);
        if (!isPasswordValid) {
            res.status(400).send({'msg':'password is incorrect'});
        }


        // if password is correct, sign jwt accessToken
        if (isPasswordValid) {

            const user = {
                id : userAccount.id,
                name : userAccount.name,
            }

            console.info(`user_id--> ${user.id}`);
            console.info(`user_name--> ${user.name}\n`);
            
            // generate an access accessToken
            const accessToken = jwt.sign(user, jwtsecret) //jwtsecret is: 'jwt-secr3t'
            console.info(`accessToken--> ${accessToken}\n\n`);
            console.info(`jwtsecret--> ${jwtsecret}\n\n`);
            
           
            const authorization = `Bearer ${accessToken}`;
            const authzHeader = req.headers['authorization'] = authorization;
            console.log(`authzHeader will save as--->  'authorization': ${authzHeader}`);

            // store the authzHeader in a cookie
            res.cookie('authorization', authzHeader , {maxAge:55000, httpOnly: true}); //55seconds

            return res.status(200).json({'msg':`${userAccount.name} log-in successful`,accessToken,jwtsecret});
            
        }else{
            res.status(400).send({'msg':'password not valid, log-in failed'});
        }
    } catch (err) {
        res.status(500).json({'msg': 'server Error'});
    }
});



// get one user by id
app.get('/user/:id', (req, res)=>{
    
    try {
        
        const user = usersList.find((user)=>user.user_id === req.params.id);

        if(user){
            return res.status(200).json({msg: 'user query valid',user});
        }else{
            return res.status(404).send({'msg': 'user not found'});
        }

    } catch (error) {
        return res.status(500).send('resquest not granted');
    }
});



// edit user's data (eg: password)
app.put('/user/update/:id',authorizeUser_by_ID_fromCookie, async (req, res)=>{
    const user = usersList.find((user)=>user.user_id === req.params.id);
    
    if(!user){
        return res.status(404).send({'msg': 'user not found'});
    }

    console.log(`fron Edit password, user.password b4 edit--> ${user.password}`);
    console.log(`fron Edit password, new password--> ${req.body.password}`);

    try {

        if (bcrypt.compare(req.body.password, user.password) === true){
            throw Error("new password matches old");
        }else{

            // update the database with a hashed version of the new password
            let newHashedPassword;
            newHashedPassword = await bcrypt.hash(req.body.password, 10);
            user.password = newHashedPassword;
            
            console.log(`fron Edit password, new Hashed-password--> ${user.password}`);
        };
    
    } catch (error) {
        console.log(`ERROR: from try/catch edit-user-password--> ${error}`);
    }

});



// remove user from database
app.delete('/user/delete_user/:id', authorizeUser_by_ID_fromCookie, (req, res)=>{

    try {
        const find_user = usersList.find((user)=> user.id === req.params.id);
        const find_userIndex = usersList.findIndex((user)=> user.id === req.params.id);

        if (find_user.id !== req.params.id) {
            return res.status(401).json({'err': 'access denied'});
        }

        if (!find_user) {
            return res.status(404).json({'err': 'invalid credential'});
        }

        // delete user that matches the index using .splice( ) method
        const removeIndex_match = userDB.splice(find_userIndex, 1)[0];
        console.log(`${removeIndex_match.name} account delete request done.`);

        // return res.status(202).json(userDB);
        return res.send(userDB).json({'msg': `\n\n${removeIndex_match.name} account delete request done.`});

    } catch (error) {
        console.log();
    }

});



// logout user
app.delete('/user/logout', authorizeUser_by_ID_fromCookie, (req, res)=>{
    console.log('user account log out');
    res.clearCookie('authorization')
        .status(204).json({'msg': 'account logged out'});
});


// protected route
app.get('/user/dashboard',authorizeUser_by_ID_fromCookie, (req, res)=>{
    console.log('\n\n\nuser dashboard route');

    try {
    res.status(200).send(`${req.user.name} Dashboard`);
        
    } catch (error) {
        console.log('token error')
    }

});
