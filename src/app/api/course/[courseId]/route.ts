import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/dbConnect';
import Course from '@/app/models/Course';
import User from '@/app/models/User';
import { auth } from '../../../../../auth';

export async function GET(req: NextRequest, { params }: { params: { courseId: string } }) {
  const session = await auth();
  const { courseId } = await params;

  try {
    await connectDB(); // Ensure the database connection
    const course = await Course.findOne({ courseId });

    if (!course) {
      return NextResponse.json({ message: 'Course not found' }, { status: 404 });
    }

    // Check for session
    if (session) {
      const user = await User.findOne({ _id: session.user?.id });

      // Check if the course is already purchased
      const hasBoughtCourse = user?.coursesBought.includes(courseId);

      return NextResponse.json(
        {
          course,
          courseIncluded: hasBoughtCourse, // true if purchased, false otherwise
        },
        { status: 200 }
      );
    }

    // If no session, just return course data
    return NextResponse.json(
      {
        course,
        courseIncluded: false, // User not logged in, so assume not purchased
      },
      { status: 200 }
    );
  } catch (error) {
    console.error(error);
    return NextResponse.json({ message: 'Server error' }, { status: 500 });
  }
}