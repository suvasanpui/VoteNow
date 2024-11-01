import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { handleError, handleSuccess } from "../utils";
import { ToastContainer } from "react-toastify";

function Signup() {
  const [signupinfo, setsignupinfo] = useState({
    name: "",
    email: "",
    contact: "",
    uidaiNo: "",
    address: "",
    age: "",
    password: "",
  });

  const navigate = useNavigate();

  //responsible for from input handle and store in a db in nodejs
  const handleSignup = async (e) => {
    e.preventDefault(); //without reload browser
    const { name, email, contact, uidaiNo, address, age, password } =
      signupinfo;
    if (
      !name ||
      !email ||
      !contact ||
      !uidaiNo ||
      !address ||
      !age ||
      !password
    ) {
      return handleError("All field are require");
    }

    try {
      //backend http url where user data store that are create in a node
      const url = "http://localhost:8000/user/signup";
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(signupinfo),
      });
      const result = await response.json();
      console.log(result);
      const { token, message, error } = result;
      if (token) {
        handleSuccess(message);
        setTimeout(() => {
          navigate("/login");
        }, 1000);
      } else if (error) {
        const details = error?.details[0].message;
        return handleError(details);
      } else {
        return handleError("some error found");
      }
    } catch (err) {
      return handleError(err);
    }
  };

  //this function is responsible for store a value in useState hook array when i given a input in a form
  const handleChange = (e) => {
    const { name, value } = e.target;
    //console.log(name,value);
    const copysignupinfo = { ...signupinfo };
    copysignupinfo[name] = value;
    setsignupinfo(copysignupinfo);
  };
  return (
    <div>
      <div className="bg-gray-50 font-[sans-serif]">
        <div className="min-h-screen flex flex-col items-center justify-center py-6 px-3">
          <div className="max-w-md w-full">
            <a href="#">
              <img className="w-40 mb-8 mx-auto block" />
            </a>

            <div className="p-8 rounded-2xl bg-white shadow">
              <h2 className="text-gray-700 text-center text-3xl font-bold pb-6">
                Registration
              </h2>
              <form onSubmit={handleSignup}>
                <div className="grid sm:grid-cols-2 gap-8">
                  <div>
                    <label className="text-gray-800 text-sm mb-2 block">
                      Name
                    </label>
                    <input
                      onChange={handleChange}
                      name="name"
                      type="text"
                      className="text-gray-800 bg-gray-100 bg-white border border-gray-300 w-full text-sm px-4 py-3 rounded-md outline-blue-500"
                      placeholder="Enter Name"
                      value={signupinfo.name}
                    />
                  </div>
                  <div>
                    <label className="text-gray-800 text-sm mb-2 block">
                      Email Id
                    </label>
                    <input
                      onChange={handleChange}
                      name="email"
                      type="email"
                      className="text-gray-800 bg-white border bg-gray-100 border-gray-300 w-full text-sm px-4 py-3 rounded-md outline-blue-500"
                      placeholder="Enter email"
                      value={signupinfo.email}
                    />
                  </div>
                  <div>
                    <label className="text-gray-800 text-sm mb-2 block">
                      Contact No.
                    </label>
                    <input
                      onChange={handleChange}
                      name="contact"
                      type="text"
                      className="text-gray-800 bg-white border bg-gray-100 border-gray-300 w-full text-sm px-4 py-3 rounded-md outline-blue-500"
                      placeholder="Enter Contact No."
                      value={signupinfo.contact}
                    />
                  </div>

                  <div>
                    <label className="text-gray-800 text-sm mb-2 block">
                      Addhar No.
                    </label>
                    <input
                      onChange={handleChange}
                      name="uidaiNo"
                      type="number"
                      className="text-gray-800 bg-white border bg-gray-100 border-gray-300 w-full text-sm px-4 py-3 rounded-md outline-blue-500"
                      placeholder="Enter Addhr No."
                      value={signupinfo.uidaiNo}
                    />
                  </div>

                  <div>
                    <label className="text-gray-800 text-sm mb-2 block">
                      Address
                    </label>
                    <input
                      onChange={handleChange}
                      name="address"
                      type="text"
                      className="text-gray-800 bg-white border bg-gray-100 border-gray-300 w-full text-sm px-4 py-3 rounded-md outline-blue-500"
                      placeholder="Enter Address"
                      value={signupinfo.address}
                    />
                  </div>

                  <div>
                    <label className="text-gray-800 text-sm mb-2 block">
                      Age
                    </label>
                    <input
                      onChange={handleChange}
                      name="age"
                      type="number"
                      className="text-gray-800 bg-white border bg-gray-100 border-gray-300 w-full text-sm px-4 py-3 rounded-md outline-blue-500"
                      placeholder="Enter Age"
                      value={signupinfo.age}
                    />
                  </div>
                  <div>
                    <label className="text-gray-800 text-sm mb-2 block">
                      Password
                    </label>
                    <input
                      onChange={handleChange}
                      name="password"
                      type="password"
                      className="text-gray-800 bg-white border bg-gray-100 border-gray-300 w-full text-sm px-4 py-3 rounded-md outline-blue-500"
                      placeholder="Enter password"
                      value={signupinfo.password}
                    />
                  </div>
                  <div>
                    <label className="text-gray-800 text-sm mb-2 block">
                      Confirm Password
                    </label>
                    <input
                      name="cpassword"
                      type="password"
                      className="text-gray-800 bg-white border bg-gray-100 border-gray-300 w-full text-sm px-4 py-3 rounded-md outline-blue-500"
                      placeholder="Enter Confirm password"
                    />
                  </div>
                  <div className="flex items-center">
                    <input
                      id="remember-me"
                      name="remember-me"
                      type="checkbox"
                      className="h-4 w-4 shrink-0 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                    />
                    <label
                      for="remember-me"
                      className="text-gray-800 ml-3 block text-sm"
                    >
                      I accept the{" "}
                      <a
                        href="#"
                        className="text-blue-600 font-semibold hover:underline ml-1"
                      >
                        Terms and Conditions
                      </a>
                    </label>
                  </div>
                </div>

                <div className="!mt-12">
                  <button
                    type="submit"
                    className="w-full py-3 px-4 text-sm tracking-wider font-semibold rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none"
                  >
                    Create an account
                  </button>
                </div>
                <p className="text-gray-800 text-sm mt-6 text-center">
                  Already have an account?{" "}
                  <Link
                    to="/login"
                    className="text-blue-600 font-semibold hover:underline ml-1"
                  >
                    Login here
                  </Link>
                </p>
              </form>
              <ToastContainer/>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Signup;
