## Endpoints

| URL                  | HTTP method | Auth | JSON Response   |
| -------------------- | ----------- | ---- | --------------- |
| /login               | POST        |      | user's token    |
| /questions           | GET         | Y    | all subjects    |
| /register            | POST        |      | new user        |
| /ask/quesitonid      | GET         | Y    | ask a question  |
| /help/questionid     | GET         | Y    | help for user   |
| /question/questionid | DELETE      | Y    | delete subject  |
| /new                 | POST        | Y    | create subject  |
| /user/id             | DELETE      | Y    | Delete user     |
| /chats               | GET         | Y    | Get users match |
| /chats/id            | POST        | Y    | Send a message  |
| /profile             | GET         | Y    | Get users date  |
