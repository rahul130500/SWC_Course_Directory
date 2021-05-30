const Assignment = require("../models/assignment");
const Course = require("../models/course");
const User = require("../models/user");
const fs = require("fs");

exports.getAssignments = async (req, res) => {
  try {
    const assignments = await Assignment.find({ course_id: req.params.courseid });
    const courses_data = await Course.find({ course_id: req.params.courseid });
    res.render("admin/assignments/index", {
      user: req.user,
      courses_data: courses_data,
      assignments: assignments,
    });
  } catch (error) {
    console.log(error.message);
  }
};

exports.addAssignmentForm = async (req, res) => {
  try {
    const assignments = await Assignment.find({ course_id: req.params.courseid });
    const courses_data = await Course.find({ course_id: req.params.courseid });
    return res.render("admin/assignments/add", {
      user: req.user,
      courses_data: courses_data,
    });
  } catch (error) {
    console.log(error.message);
  }
};

exports.postAssignment = async (req, res) => {
  try {
    var course_id = req.params.courseid;
    var { name } = req.body;
    const path = req.file ? req.file.filename : filepath;
    if (!path) {
      console.log("path not added");
      return res.redirect("/coursedirectory/admin");
    }
    const newAssignment = await new Assignment({
      course_id,
      name,
      filepath: path,
    }).save();
    if (!newAssignment) {
      console.log("Assignment Not added");
      const url = "/coursedirectory/admin/" + course_id + "/assignments";
      res.redirect(url);
    }
    console.log("Successfully added new Assignment");
    const url = "/coursedirectory/admin/" + course_id + "/assignments";
    return res.redirect(url);
  } catch (error) {
    console.log(error.message);
  }
};

exports.getEditForm = async (req, res) => {
  try {
    const assignment = await Assignment.findById(req.params.assignmentid);
    const courses_data = await Course.find({course_id: req.params.courseid});
    console.log(courses_data);
    return res.render("admin/assignments/edit", {
      user: req.user,
      courses_data: courses_data,
      assignment: assignment,
    });
  } catch (error) {
    console.log(error.message);
  }
};

exports.postEditForm = async (req,res) => {
  try {
    var course_id = req.params.courseid;
    var { name } = req.body;
    // var newLecture;
    // if (!req.file) {
    //    newLecture = {
    //     course_id,
    //     name
    //   };
    // }
    // else {
    //    newLecture = {
    //     course_id,
    //     name,
    //     filepath: req.file.filename,
    //   };
    // }
    // const added = await Lecture.findByIdAndUpdate(req.params.lectureid, newLecture);
    // if (!added) {
    //   console.log("Lecture Not added");
    // }
    // console.log("Successfully added new lecture");
    console.log(req.body);
    const url = "/coursedirectory/admin/" + course_id + "/assignments";
    return res.redirect(url);
  } catch (error) {
    console.log(error.message);
  }
};

exports.deleteAssignment = async (req, res) => {
  try {
    var course_id = req.params.courseid;
    const id = req.params.assignmentid;
    const assignment = await Assignment.findById(id);
    fs.unlinkSync(`uploads/assignments/${assignment.filepath}`);
    console.log("successfully deleted!");
    await Assignment.findByIdAndRemove(id);
    console.log("successfully deleted!");
    await Assignment.findByIdAndRemove(id);
    const url = "/coursedirectory/admin/" + course_id + "/assignments";
    return res.redirect(url);
  } catch (err) {
    console.log(err);
    const url = "/coursedirectory/admin/" + course_id + "/assignments";
    return res.redirect(url);
  }
};

exports.getOneAssignment = async (req, res) => {
  try {
    const id = req.params.assignmentid;
    const assignment = await Assignment.findById(id);
    console.log(assignment.filepath);
    const filePath = "uploads/assignments/" + assignment.filepath;
    console.log(filePath);
    fs.readFile(filePath, (err, data) => {
      res.contentType("application/pdf");
      return res.send(data);
    });
  } catch (error) {
    console.log(error.message);
  }
};
