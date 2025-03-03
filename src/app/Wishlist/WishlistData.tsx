"use client";

import { useSession } from "next-auth/react";
import { useState, useEffect } from "react";
import Image from "next/image";
import ProfileSection from "../Cart/ProfileSection";
import { FaUsers } from "react-icons/fa";
import { AiOutlineShoppingCart } from "react-icons/ai";
import formatStudents from "@/lib/formatStudents";
import Loader from "@/components/ui/Loader";
import { TrashIcon } from "@heroicons/react/24/outline";
import { toast } from "react-toastify";
import { ClipLoader } from "react-spinners";

interface ICourse {
  _id: string;
  name: string;
  shortDescription: string;
  image: string;
  price: {
    current: number;
    original: number;
  };
  studentsEnrolled: number;
  courseId: number;
}

const Wishlist = () => {
  const [wishlist, setWishlist] = useState<ICourse[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [isRemoving, setIsRemoving] = useState<boolean>(false);
  const [isWishing, setIsWishing] = useState<boolean>(false);
  const { data: session } = useSession();

  useEffect(() => {
    const fetchWishlistCourses = async () => {
      setLoading(true);
      try {
        const response = await fetch("/api/wishlistCourses");
        if (!response.ok) throw new Error("Error fetching courses");
        const data: ICourse[] = await response.json();
        setWishlist(data);
      } catch (error) {
        console.error("Error fetching wishlist data", error);
      } finally {
        setLoading(false);
      }
    };

    fetchWishlistCourses();
  }, []);

  const removeFromWishlist = async (courseId: number) => {
    try {
      setIsRemoving(true);
      const response = await fetch("/api/removeWishlistCourse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ courseId }),
      });

      if (!response.ok) throw new Error("Failed to remove course");

      setWishlist(wishlist.filter((course) => course.courseId !== courseId));
      toast.success("Course removed successfully");
    } catch (error) {
      setIsRemoving(false);
      console.error("Error removing course:", error);
    } finally {
      setIsRemoving(false);
    }
  };

  // Function to move course to cart
  const moveToCart = async (courseId: number) => {
    setIsWishing(true);
    try {
      const response = await fetch("/api/addCart", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ courseId }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || "Something went wrong");
      }
      removeFromWishlist(courseId);
      setIsWishing(false);
      toast.success("Course is moved to your Cart");
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error(error);
        console.log("Adding Wishlist has developed some issue.");
      } else {
        setIsWishing(false);
        console.error("Something went Wrong on client side.");
      }
    } finally {
      setIsWishing(false);
    }
  };

  if (loading) return <Loader />;

  return (
    <div className="min-h-screen flex flex-col md:flex-row bg-gray-100">
      {/* Profile Section */}
      <div className="md:w-1/4 w-full p-6 bg-white shadow-lg flex flex-col items-center md:sticky md:top-0">
        <ProfileSection session={session} />
      </div>

      {/* Wishlist Section */}
      <main className="flex-1 p-6 md:p-10">
        <h1 className="text-2xl md:text-3xl font-bold text-purple-800 mb-6 text-center md:text-left">
          Wishlist
        </h1>

        {/* Show empty wishlist message */}
        {wishlist.length === 0 ? (
          <div className="text-center text-gray-500 text-lg mt-10">
            🎈 Your Wishlist is empty. Start adding courses!
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {wishlist.map((course) => (
              <div
                key={course._id}
                className="bg-white rounded-lg shadow-md p-4 relative"
              >
                {/* Course Image */}
                <Image
                  src={course.image}
                  alt={course.name}
                  width={300}
                  height={180}
                  className="rounded-lg"
                />

                {/* Course Details */}
                <div className="mt-4">
                  <h3 className="text-lg font-semibold text-indigo-700">
                    {course.name}
                  </h3>
                  <p className="text-sm text-gray-500">
                    {course.shortDescription}
                  </p>

                  {/* Student Count */}
                  <div className="flex items-center mt-2">
                    <FaUsers className="text-purple-600 mr-2" />
                    <span className="text-sm text-gray-600 ml-2">
                      +{formatStudents(course.studentsEnrolled)} students
                    </span>
                  </div>

                  {/* Pricing */}
                  <div className="flex items-center mt-2">
                    <p className="text-lg font-bold text-black">
                      ₹{course.price.current}
                    </p>
                    <p className="text-sm text-gray-400 line-through ml-2">
                      ₹{course.price.original}
                    </p>
                  </div>

                  {/* Action Buttons */}
                  <div className="flex justify-between items-center mt-4">
                    {/* Move to Cart */}
                    <button
                      onClick={() => moveToCart(course.courseId)}
                      className="flex items-center bg-blue-600 text-white px-3 py-1.5 rounded-md hover:bg-blue-700 transition"
                    >
                      {isWishing ? <ClipLoader size={15} color="white" /> : <AiOutlineShoppingCart className="mr-2" />}  Move to Cart
                    </button>

                    {isRemoving ? (
                      <ClipLoader size={30} color="red" />
                    ) : (
                      <button
                        onClick={() => removeFromWishlist(course.courseId)}
                        className="text-red-500 hover:text-red-700 transition"
                      >
                        <TrashIcon className="w-6 h-6" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
};

export default Wishlist;
