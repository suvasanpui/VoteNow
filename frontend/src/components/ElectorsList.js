import React, { useEffect, useState } from "react";
import { handleError, handleSuccess } from "../utils";
import { useNavigate } from "react-router-dom";
import { ToastContainer } from "react-toastify";

function ElectorsList() {
  const [showList, setShowList] = useState("");

  //when i click a vote button then its get elector id and the update record in a electos collection
  const handleVote=async (e)=>{
    const {value}=e.target;
    try{
      const url=`http://localhost:8000/electors/votes/${value}`;
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("loggedToken")}`,
        "Content-Type": "application/json",
      };
      const responseRes = await fetch(url, {
        method: "POST",
        headers: headers,
      });
      const result = await responseRes.json();
      handleSuccess(result);
    }catch(err){

    }
  }

  //fetch all the member record in a home page 
  const fetchRecord = async () => {
    try {
      const url = "http://localhost:8000/electors";
      //this is function to gat a token from localstorage
      const headers = {
        Authorization: `Bearer ${localStorage.getItem("loggedToken")}`,
        "Content-Type": "application/json",
      };
      const responseRes = await fetch(url, {
        method: "GET",
        headers: headers,
      });
      const result = await responseRes.json();
      console.log(result);
      setShowList(result.response);
    } catch (err) {
      handleError(err);
    }
  };
  useEffect(() => {
    fetchRecord();
  }, []);

  return (
    <div>
      <div className="px-3 py-3 font-serif font-medium text-gray-700 col-span-6 bg-slate-600">
        <div className="relative overflow-x-auto">
          <table className="w-full text-sm text-left rtl:text-right text-gray-500 dark:text-gray-400">
            <thead className="text-xs text-gray-700 uppercase bg-gray-100 dark:bg-gray-700 dark:text-gray-400">
              <tr>
                <th scope="col" className="px-6 py-3">
                  Name
                </th>
                <th scope="col" className="px-6 py-3">
                  Party
                </th>
                <th scope="col" className="px-6 py-3">
                  Participate
                </th>
              </tr>
            </thead>
            <tbody>
              {Array.isArray(showList) &&
                showList.map((data, index) => (
                  <tr className="bg-white dark:bg-gray-800" key={index}>
                    <th
                      scope="row"
                      className="px-6 py-4 font-medium text-gray-900 whitespace-nowrap dark:text-white"
                    >
                      {data.name}
                    </th>
                    <td className="px-6 py-4">{data.party}</td>
                    <td className="m-6 p-4">
                      <button
                      name={data.party}
                        type="button"
                        className="text-white bg-blue-700 hover:bg-blue-800 focus:outline-none focus:ring-blue-300 font-small rounded-lg text-sm px-4 py-2 text-center dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800 ml-7"
                        value={data.id}
                        onClick={handleVote}
                      >
                        Vote
                      </button>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
          <ToastContainer/>
        </div>
      </div>
    </div>
  );
}

export default ElectorsList;
