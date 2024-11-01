import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ToastContainer } from "react-toastify";
import { handleError, handleSuccess } from "../utils";
import Nav from "./../components/Navbar";
import ElectorsList from "../components/ElectorsList";

function Home() {
  const [allresult, setAllresult] = useState("");

  //fetch all the member record
  const fetchRecord = async () => {
    try {
      const url = "http://localhost:8000/user/profile";
      //this is function to gat a token from localstorage
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("loggedToken")}`,
        "Content-Type": "application/json",
      };
      const response = await fetch(url, {
        method: "GET",
        headers: headers,
      });
      const result = await response.json();
      console.log(result);
      setAllresult(result.user);
    } catch (err) {
      handleError(err);
    }
  };
  
  useEffect(() => {
    fetchRecord();
  }, []);

  return (
    <>
      <Nav />
      <div className="m-20">
      {
        
        !allresult.isVoted ?<ElectorsList/>:"you are already given a vote"
      
      }
        
      </div>
    </>
  );
}

export default Home;
