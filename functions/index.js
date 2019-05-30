const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp(functions.config().firebase);
// // Create and Deploy Your First Cloud Functions
// // https://firebase.google.com/docs/functions/write-firebase-functions
//
// exports.helloWorld = functions.https.onRequest((request, response) => {
//  response.send("Hello from Firebase!");
// });

//This function set attributes for a newly created user
exports.doNewUserPopulate = functions.auth.user().onCreate(user => {
  const claims = admin
    .auth()
    .setCustomUserClaims(user.uid, { admin: false, role: "new" });
  return claims;
});

//Probably an insecure implementation, if attacker manages to intercept admin's id
// Requires {userId: target user id,
//           adminStatus: bool new status,
//             role: string new role }

exports.changeUserAdminStatus = functions.https.onCall((data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('failed-precondition', 'The function must be called ' +
    'while authenticated.');
  }
  //Preventing accidental mistakes
  if (context.auth.uid === data.userId) {
    throw new functions.https.HttpsError('failed-precondition', 'Un administrateur ne peut se révoquer ses droits !');
  }
  admin.auth().getUser(context.auth.uid).then((user) => {
      if(user.customClaims.admin){
        admin.auth().getUser(data.userId).then((userTarget) => {
        if(userTarget.customClaims){
          return admin.auth().setCustomUserClaims(data.userId, { admin: !userTarget.customClaims.admin, role: 'new'});
        } else {
            return admin.auth().setCustomUserClaims(data.userId, { admin: false, role: 'new'});
          }
      });
    }
  });
});


// Requires {userId: target user id}

exports.getUserAdminStatus = functions.https.onCall((data, context) => {

    if (!context.auth) {
      throw new functions.https.HttpsError('failed-precondition', 'The function must be called ' +
      'while authenticated.');
    }
    return admin.auth().getUser(context.auth.uid).then((user) => {
        if(user.customClaims.admin){
            admin.auth().getUser(data.userId).then((user) => {
                    return user.customClaims;
            }).catch(() => {
                throw new functions.https.HttpsError('failed-precondition', 'Invalid User Id.');
            })
        } else {
            throw new functions.https.HttpsError('failed-precondition', 'The function must be called ' +
      'by an administrator.');
        }
    });
  });
  
exports.getAllUsers = functions.https.onCall((data, context) => {
  if(!data.page) {
    throw new functions.https.HttpsError('failed-precondition', 'The function must be called ' +
      'with page value.');
  }
  return admin.auth().listUsers(100, data.page).then((userList) => {
    return {...userList.users};
  });
});