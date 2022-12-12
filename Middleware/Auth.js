let jwt = require('jsonwebtoken')
const Auth = (req, res, next) => {
  
  try {
    
    const token = req.header("x-auth-token");
    
    if (!token)
      return res
        .status(401)
        .json({ msg: "No authentication token, authorization denied." });

    const verified = jwt.verify(token, 'melih');
    if (!verified)
      return res
        .status(401)
        .json({ msg: "Token verification failed, authorization denied." });

    req.user = verified.id;
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};


module.exports = Auth;