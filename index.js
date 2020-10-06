/* write the code to run app.js here */
const app = require("./app");
const PORT = 3001;

app.listen(PORT, () => {
  console.log(`app listening on port ${PORT}`);
});
