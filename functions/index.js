const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp(functions.config().firebase);
// // Create and Deploy Your First Cloud Functions
// // https://firebase.google.com/docs/functions/write-firebase-functions
//
// exports.helloWorld = functions.https.onRequest((request, response) => {
//  response.send("Hello from Firebase!");
// });

/******
 * Parses a query result for a
 * given collection of files
 * hasPower describes administrative
 * powers, if isRecuded is set to true
 * function will return a short summary
 */


const parseFileSummary = (queryResult, hasPower, isReduced) => {
  const fileList = [];
  queryResult.forEach((doc) => {
    admin.auth().getUser(doc.data().info.student).then((student) => {
      const userName = student.displayName;
      const info = doc.data().info;
      info.student = userName;
      if(isReduced){
        fileList.push({
          id: doc.id,
          info: info,
          genComment: doc.data().sections[0].comment
        });
      } else {
      fileList.push({
        id: doc.id,
        info: info,
        sections: doc.data().sections
      });
    }
    })
    })
  return { hasPower: hasPower, files: fileList };
}



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
//             newRole: string new role }

exports.changeUserAdminStatus = functions.https.onCall((data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "The function must be called " + "while authenticated."
    );
  }
  //Preventing accidental mistakes
  if (context.auth.uid === data.userId) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "Un administrateur ne peut se révoquer ses droits !"
    );
  }
  admin.auth().getUser(context.auth.uid).then(user => {
    if (user.customClaims.admin) {
      admin.auth().getUser(data.userId).then(userTarget => {
        if (userTarget.customClaims) {
          return admin
            .auth()
            .setCustomUserClaims(data.userId, {
              admin: data.newAdminStatus,
              role: data.newRole
            });
        } else {
          return admin
            .auth()
            .setCustomUserClaims(data.userId, { admin: false, role: "new" });
        }
      });
    }
  });
});

// Requires {userId: target user id}

exports.getUserAdminStatus = functions.https.onCall((data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "The function must be called " + "while authenticated."
    );
  }
  return admin.auth().getUser(context.auth.uid).then(user => {
    if (user.customClaims.admin) {
      admin
        .auth()
        .getUser(data.userId)
        .then(user => {
          return user.customClaims;
        })
        .catch(() => {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Invalid User Id."
          );
        });
    } else {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "The function must be called " + "by an administrator."
      );
    }
  });
});

exports.getAllUsers = functions.https.onCall((data, context) => {
  if (!data.page) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "The function must be called " + "with page value."
    );
  }
  return admin.auth().listUsers(100, data.page).then(userList => {
    return { ...userList.users };
  });
});

exports.getStudents = functions.https.onCall((data, context) => {
  return admin.auth().getUser(context.auth.uid).then(thisUser => {
    const userClaims = thisUser.customClaims;
    if (!context.auth || !userClaims) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "The function must be called " + "while authenticated."
      );
    }
    if (!userClaims.admin || userClaims.role === "student") {
      throw new functions.https.HttpsError(
        "failed-precondition",
        "Access Denied."
      );
    }
    return admin.auth().listUsers(100).then(userList => {
      return userList.users
        .map(user => {
          if (user.customClaims.role === "student") {
            return {
              displayName: user.displayName,
              email: user.email,
              customClaims: user.customClaims
            };
          }
        })
        .filter(el => el != null);
    });
  });
});

exports.getFileList = functions.https.onCall((data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "The function must be called " + "while authenticated."
    );
  }
  return admin.auth().getUser(context.auth.uid).then(curUser => {
    const hasPower =
      curUser.customClaims.admin ||
      curUser.customClaims.role === "admin" ||
      curUser.customClaims.role === "instructor";
    if (hasPower && data) {
      if(!data.user){
        throw new functions.https.HttpsError(
          "failed-precondition",
          "[getFileList] Requires user id as param 'user'."
        );
      }
      return admin
        .firestore()
        .collection("files")
        .where("user", "==", data.user)
        .orderBy('info.date', 'desc')
        .then(files => {
          return parseFileSummary(files, hasPower, true);
        })
        .catch(err => {
          throw new functions.https.HttpsError(
            "failed-precondition",
            "Invalid User ID."
          );
        });
    } else if (hasPower) {
      return admin.firestore().collection("files").orderBy('info.date', 'desc').get().then(files => {
        return parseFileSummary(files, hasPower, true);
      }).catch(err => ['No Data']);
    } else {
      return admin
        .firestore()
        .collection("files")
        .where("user", "==", context.auth.uid)
        .get()
        .then(files => {
          return parseFileSummary(files, hasPower, true);
        }).catch((err) => (console.log('No Data')));
    }
  });
});
