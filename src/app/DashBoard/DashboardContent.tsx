"use client";

import { useState, useEffect } from "react";
import Sidebar from "./Sidebar";
import ProfileSection from "./ProfileSection";
// import VideoCard from "./VideoCard";
import ImageCard from "./ImageCard";
import { Bars3Icon, XMarkIcon } from "@heroicons/react/24/outline";
import NoCoursesAvailable from "./NoCoursesAvailable";
import Loader from "@/components/ui/Loader";




const DashboardContent = () => {
  const [courses, setCourses] = useState([]);
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(false);
  const [isEmpty, setIsEmpty] = useState<boolean>(false);
  const [fetchingUserCourses, setFetchingUserCourses] = useState<boolean>(false);
  useEffect(() => {
    setFetchingUserCourses(true);
    const fetchCourses = async () => {
      try {
        const response = await fetch("/api/userCourses");
        if (response.ok) {
          const data = await response.json();
          if(data.length > 0){
            setCourses(data);
          }
          else{
            setIsEmpty(true);
          }
        } else {
          console.error("Failed to fetch courses");
        }
      } catch (error) {
        console.error("Error fetching courses:", error);
      }
      finally {
        setFetchingUserCourses(false);
      }
    };

    fetchCourses();
  }, []);

  return (
    <div className="flex min-h-screen bg-white">
      {/* Sidebar */}
      <div className={`w-64 bg-white text-gray-800 border-r border-gray-200 ${sidebarOpen ? "block" : "hidden"} md:block`}>
        <Sidebar />
      </div>

      {/* Main Content */}
      <div className="flex-1 p-4 md:pl-8">
        {/* Top Bar */}
        <div className="flex justify-between items-center mb-6">
          <input
            type="text"
            placeholder="Search your Course here..."
            className="w-full md:max-w-md p-3 rounded-lg border border-gray-300 focus:outline-none"
          />
          <button className="ml-4 p-3 rounded-lg bg-gray-100 text-gray-500 hover:bg-gray-200">
            Settings
          </button>

          {/* Mobile Hamburger Menu */}
          <button className="md:hidden p-3 text-gray-500" onClick={() => setSidebarOpen(!sidebarOpen)}>
            {sidebarOpen ? <XMarkIcon className="h-6 w-6" /> : <Bars3Icon className="h-6 w-6" />}
          </button>
        </div>

        {/* Header Section */}
        <div className="bg-purple-600 text-white p-4 rounded-lg mb-6">
          <h2 className="text-xl font-bold mb-4">
            Sharpen Your Skills With Professional Online Courses
          </h2>
          <button className="bg-black text-white px-6 py-2 rounded-lg flex items-center space-x-2">
            Join Now
          </button>
        </div>

        {/* Continue Watching */}
        <h3 className="text-xl font-semibold mb-6">Available Courses</h3>
        {
        isEmpty? <NoCoursesAvailable /> : 
        // fetchingUserCourses? <Loader /> : 
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6">
          {fetchingUserCourses ? <Loader /> : 
          courses.map((course) => (
            <ImageCard key={course._id} course={course} />
          ))
          }
        </div>
        }
        
      </div>
      {/* Profile Section */}
      {/* <div className="hidden md:block w-72 bg-white border-l border-gray-200">
        <ProfileSection />
      </div> */}
    </div>
  );
};

export default DashboardContent;