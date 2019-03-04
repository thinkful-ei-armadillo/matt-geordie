'use strict';

const AuthService = require('../auth/auth-service');

function requireAuth(req, res, next){
  
  const authToken = req.get('Authorization') || '';

  let bearerToken;
  if(!authToken.toLowerCase().startsWith('bearer ')){
    return res.status(401).json({error: 'Missing token'});
  } else {
    bearerToken = authToken.slice(7, authToken.length);
  }

  const [tokenUserName, tokenPassword] = AuthService.parseBearerToken(bearerToken);

  if(!tokenUserName || !tokenPassword){
    return res.status(401).json({error : 'Authorization needed'});
  }

  AuthService.getUserWithUserName(req.app.get('db'), tokenUserName)
    .then(user => {
      if(!user || user.password !== tokenPassword){
        return res.status(401).json({
          error: 'Authorization needed'
        });
      }

      req.user = user;

      next();
    }).catch(next);

  next();
}

module.exports = {
  requireAuth,
};