import dotenv from "dotenv";
dotenv.config();
// help
import { ObjectId } from "mongodb";
import express from "express";
import cors from "cors";
import { MongoClient, ServerApiVersion } from "mongodb";
import admin from "firebase-admin";
const app = express();
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY)
app.use(cors(
    {
        origin: [
            "http://localhost:5173",
            "https://scholarship-platform-2f772.web.app",
        ],
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
        credentials: true,
    }
));
// for git commit 
app.use(express.json());
const port = 5000;

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            clientId: process.env.FIREBASE_CLIENT_ID,
            privateKeyId: process.env.FIREBASE_PRIVATE_KEY_ID,
            authUri: process.env.FIREBASE_AUTH_URI,
            tokenUri: process.env.FIREBASE_TOKEN_URI,
            authProviderX509CertUrl: process.env.FIREBASE_AUTH_PROVIDER_CERT_URL,
            clientC509CertUrl: process.env.FIREBASE_CLIENT_CERT_URL,
        }),
    });
}
const verifyFirebaseToken = async (req, res, next) => {

    try {
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith("Bearer ")) {
            return res.status(401).json({ error: "Unauthorized - No Token" });
        }
        const idToken = authHeader.split(" ")[1];

        const decodedUser = await admin.auth().verifyIdToken(idToken);
        req.user = decodedUser; // 🔁 Use req.user
        next();
    } catch (error) {
        return res.status(403).json({ error: "Forbidden - Invalid/Expired Token" });
    }
};

const verifyAdmin = async (req, res, next) => {
    try {
        const email = req.user.email; // req.user is set by verifyFirebaseToken
        const userInDB = await userCollection.findOne({ email });

        if (!userInDB || userInDB.role !== "admin") {
            return res.status(403).json({ error: "Access denied. Admins only." });
        }

        next(); // ✅ Admin verified
    } catch (error) {
        console.error("Admin verification error:", error);
        res.status(500).json({ error: "Internal server error" });
    }
};

const uri = process.env.MONGODB_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});
let userCollection;
let scholarshipCollection;
let appliedScholarshipCollection;
async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();
        const db = client.db("scholarshipDB");
        userCollection = db.collection("users");
        scholarshipCollection = db.collection("scholarships");
        appliedScholarshipCollection = db.collection("appliedScholarships")
        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } catch (err) {
        console.error("Error connecting to MongoDB:", err);
    }
}


run().catch(console.dir);


// this is for applied scholarship delete
// DELETE an applied scholarship by ID
app.delete('/applied-scholarship/:applicationId', async (req, res) => {
    try {
        const { applicationId } = req.params;
        const query = { _id: new ObjectId(applicationId) };

        const result = await appliedScholarshipCollection.deleteOne(query);

        if (result.deletedCount === 1) {
            res.send({
                success: true,
                message: "Application deleted successfully",
                result,
            });
        } else {
            res.status(404).send({
                success: false,
                message: "Application not found",
            });
        }
    } catch (error) {
        console.error("Error deleting application:", error);
        res.status(500).send({
            success: false,
            message: "Internal server error",
        });
    }
});

// this is for applied scholarship status update
// PATCH /scholarship/:id — Update paymentStatus and paidBy
app.patch('/applied-scholarship/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const { status } = req.body;

        if (!status) {
            return res.status(400).send({ message: 'Missing status in request body' });
        }

        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
            $set: {
                status: status,
            },
        };

        const result = await appliedScholarshipCollection.updateOne(filter, updateDoc);

        if (result.modifiedCount === 0) {
            return res.status(404).send({ message: 'Scholarship not found or already updated' });
        }

        res.send({
            success: true,
            message: 'Scholarship payment status updated successfully',
            result
        });
    } catch (error) {
        console.error('Error updating scholarship:', error);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// this patch for feedback update in applied scholarship
app.patch('/applied-scholarship-feedback/:id', async (req, res) => {
    const id = req.params.id;
    const { feedback } = req.body;
    const filter = { _id: new ObjectId(id) };
    const options = { upsert: true };
    const updateDoc = {
        $set: {
            feedback: feedback || "",
            updatedAt: new Date()
        },
    }
    const result = await appliedScholarshipCollection.updateOne(filter, updateDoc, options);
    res.send(result);
})

// this is for applied scholarship data
app.post('/applied-scholarship', async (req, res) => {
    try {
        const applicationData = req.body;

        const result = await appliedScholarshipCollection.insertOne(applicationData);
        res.status(201).send({ success: true, insertedId: result.insertedId });
    } catch (error) {
        console.error("❌ Failed to apply for scholarship:", error);
        res.status(500).send({ success: false, message: error.message });
    }
});
// this is for applied scholarship data getting 
app.get('/allApplied-scholarship', async (req, res) => {
    const result = await appliedScholarshipCollection.find().toArray();
    res.send(result);
})
app.get('/applied-scholarship', async (req, res) => {
    try {
        const { userEmail } = req.query;

        if (!userEmail) {
            return res.status(400).json({
                success: false,
                message: 'User email is required'
            });
        }

        const applications = await appliedScholarshipCollection
            .find({ userEmail: userEmail })
            .sort({ createdAt: -1 })
            .toArray();

        res.status(200).json({
            success: true,
            data: applications,
            count: applications.length
        });

    } catch (error) {
        console.error('Error fetching applied scholarships:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// this is for stripe payment implementation 

app.post('/create-payment-intent', async (req, res) => {
    const { amount } = req.body;

    try {
        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount * 100, // amount in cents
            currency: 'usd',
            payment_method_types: ['card'],
        });

        res.send({
            clientSecret: paymentIntent.client_secret,
        });
    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});
// this is for patch request for scholarship data
app.patch('/scholarship/:id', async (req, res) => {
    const { paymentStatus } = req.body;
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updateDoc = {
        $set: {
            paymentStatus: paymentStatus,
        },
    }
    const result = await scholarshipCollection.updateOne(filter, updateDoc);
    if (result.modifiedCount > 0) {
        res.send({
            success: true,
            message: "Payment status updated successfully",
            result
        });
    } else {
        res.send({
            success: false,
            message: "No scholarship found with the given ID",
        });
    }
})
// my scholarship review data getting by id
app.put('/MyScholarship/:universityId', async (req, res) => {
    try {
        const universityId = req.params.universityId;
        const updateFields = req.body;
        if (!updateFields || Object.keys(updateFields).length === 0) {
            return res.status(400).send({ message: 'No data provided to update' });
        }

        const filter = { _id: new ObjectId(universityId) };
        const updateDoc = {
            $push: {
                updateFields: updateFields
            }
        };

        const result = await scholarshipCollection.updateOne(filter, updateDoc);

        res.send(result)

    } catch (error) {
        console.error('Error updating scholarship:', error);
        res.status(200).send({ message: 'Internal server error', error: error.message });
    }
});
// this if for update review in this scholarship collection 

app.patch('/updateReviews/:id', async (req, res) => {
    const { id } = req.params;
    const { rating, comment } = req.body;

    try {
        // Step 1: Get the full document
        const scholarship = await scholarshipCollection.findOne({ _id: new ObjectId(id) });

        if (!scholarship || !Array.isArray(scholarship.ratings) || scholarship.ratings.length === 0) {
            return res.status(404).send({ message: 'No ratings found to update' });
        }

        // Step 2: Update last rating item
        const lastIndex = scholarship.ratings.length - 1;
        scholarship.ratings[lastIndex].point = rating;
        scholarship.ratings[lastIndex].comments = comment;
        scholarship.ratings[lastIndex].reviewDate = new Date();

        // Step 3: Save the updated ratings array
        const result = await scholarshipCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { ratings: scholarship.ratings } }
        );

        res.send({ success: true, message: 'Review updated successfully', result });
    } catch (error) {
        console.error('Update error:', error);
        res.status(500).send({ message: 'Internal server error', error: error.message });
    }
});



// this is for delete review data in scholarship collection 
app.delete('/deleteReview/:id', async (req, res) => {
    const { id } = req.params;
    const { userEmail } = req.query;

    try {
        const result = await scholarshipCollection.updateOne(
            { _id: new ObjectId(id) },
            { $pull: { ratings: { userEmail: userEmail } } }
        );

        if (result.modifiedCount === 0) {
            return res.status(404).send({ message: 'Review not found' });
        }

        res.send({ message: 'Review deleted successfully' });
    } catch (error) {
        console.error('Error deleting review:', error);
        res.status(500).send({ message: 'Internal server error', error: error.message });
    }
});

// scholarship particular data getting by email 
app.get('/reviewOfScholarship', async (req, res) => {
    const { email } = req.query;
    console.log(email);

    if (!email) {
        return res.status(400).send({ message: 'Email is required' });
    }

    try {
        const result = await scholarshipCollection.find({ 'ratings.reviewerEmail': email }).toArray();

        const filteredResult = [];

        result.forEach(item => {
            const userReviews = item.ratings.filter(r => r.reviewerEmail === email);

            userReviews.forEach(review => {
                filteredResult.push({
                    _id: item._id,
                    scholarshipName: item.scholarshipName,
                    universityName: item.universityName,
                    date: review.reviewDate || '',
                    rating: review.point || '',
                    comment: review.comments || '',
                    userEmail: review.reviewerEmail || '',
                });
            });
        });

        if (filteredResult.length === 0) {
            return res.status(404).send({ message: 'No reviews found for this email' });
        }

        res.status(200).send({
            success: true,
            message: 'All scholarship reviews retrieved successfully',
            data: filteredResult
        });

    } catch (error) {
        console.error('Error retrieving reviews:', error);
        return res.status(500).send({ message: 'Internal server error', error: error.message });
    }
});




// this end point is for updating scholarship data like comment and likes and other things
app.put('/scholarship/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const data = req.body;
        const options = { upsert: true };
        const result = await scholarshipCollection.updateOne(query, { $set: data }, options);
        res.send(result);
    } catch (error) {
        res.status(500).send({ error: 'Error updating scholarship' });
    }
})
// this end point for getting specific scholarship data by id
app.get('/scholarship/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await scholarshipCollection.findOne(query);
        if (!result) {
            return res.status(404).send({ error: 'Scholarship not found' });
        }
        res.status(200).send(result);
    } catch (error) {
        res.status(500).send({ error: 'Error retrieving scholarship' });
    }

})
// this end point is for deleting scholarship data
app.delete('/scholarship-admin/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await scholarshipCollection.deleteOne(query);
        if (result.deletedCount === 0) {
            return res.status(404).send({ error: 'Scholarship not found' });
        } else {
            return res.status(200).send({ message: 'Scholarship deleted successfully' });
        }
    } catch (error) {
        return res.status(500).send({ error: 'Error deleting scholarship' });
    }
})
// this end point is for deleting scholarship data
app.delete('/scholarship/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await scholarshipCollection.deleteOne(query);
        if (result.deletedCount === 0) {
            return res.status(404).send({ error: 'Scholarship not found' });
        } else {
            return res.status(200).send({ message: 'Scholarship deleted successfully' });
        }
    } catch (error) {
        return res.status(500).send({ error: 'Error deleting scholarship' });
    }
})
// this is for rating delete form collection
// Better version with proper filtering:
app.patch('/ratings/:reviewerEmail', async (req, res) => {
    try {
        const { reviewerEmail } = req.params;



        // Find all scholarships that contain this reviewer's email
        const updateDoc = {
            $pull: {
                ratings: { reviewerEmail }
            }
        };

        // Fix: Use proper filter to find documents with this email in ratings
        const result = await scholarshipCollection.updateMany(
            { "ratings.reviewerEmail": reviewerEmail }, // Filter to only update docs with this email
            updateDoc
        );

        res.send({
            success: true,
            message: "Ratings removed successfully",
            result
        });
    } catch (error) {
        res.status(500).send({
            success: false,
            message: "Failed to remove ratings",
            error: error.message
        });
    }
});

// this end point just for rating scholarship data
app.get('/ratings', async (req, res) => {
    try {
        const scholarships = await scholarshipCollection
            .find({}, { projection: { ratings: 1, _id: 0 } }) // শুধু ratings আর _id বাদ
            .toArray();

        res.send(scholarships);
    } catch (error) {
        console.error("Error retrieving scholarship ratings:", error);
        res.status(500).send({ error: 'Error retrieving scholarship ratings' });
    }
});
// top 6 scholarship getting endpoint 
app.get('/top-scholarships', async (req, res) => {
    try {
        const scholarships = await scholarshipCollection
            .find()
            .sort({ applicationFees: 1, scholarshipPostDate: -1 }) // ascending sort
            .limit(6)
            .toArray();

        res.send({
            success: true,
            message: 'Top 6 sorted scholarships retrieved',
            data: scholarships
        });
    } catch (error) {
        console.error('Failed to get top scholarships:', error);
        res.status(500).send({
            success: false,
            message: 'Failed to get top scholarships'
        });
    }
});
// this end point is for getting all scholarship data
app.get('/scholarship-admin', verifyFirebaseToken, verifyAdmin, async (req, res) => {

    try {
        const scholarships = await scholarshipCollection.find().toArray();
        res.send(scholarships);
    } catch (error) {
        res.status(500).send({ error: 'Error retrieving scholarships' });
    }
});
// this end point is for getting all scholarship data
app.get('/scholarship', async (req, res) => {

    try {
        const scholarships = await scholarshipCollection.find().toArray();
        res.send(scholarships);
    } catch (error) {
        res.status(500).send({ error: 'Error retrieving scholarships' });
    }
});
// this end point for admin scholarship add in the database 
app.post('/scholarship', verifyFirebaseToken, verifyAdmin, async (req, res) => {
    const scholarship = req.body;
    const result = await scholarshipCollection.insertOne(scholarship);
    if (!result || result.insertedCount === 0 || result.modifiedCount === 0) {
        return res.status(500).send({
            success: false,
            message: "❌ Failed to add scholarship"
        });
    } else {
        return res.status(200).send({
            success: true,
            message: "✅ Successfully added scholarship",
            modifiedCount: result.modifiedCount,
        });
    }
})
// this is for all login user getting data 
app.get("/users", verifyFirebaseToken, verifyAdmin, async (req, res) => {
    const result = await userCollection.find().toArray();
    res.send(result);
})
// this is for login update date 

// this end point is for role based user data
app.get("/users/role", async (req, res) => {
    const email = req.query.email;

    if (!email) {
        return res.status(400).send({
            success: false,
            message: "❌ Email is required",
        });
    }

    try {
        const user = await userCollection.findOne({ email });

        if (!user) {
            return res.status(404).send({
                success: false,
                message: "❌ User not found",
            });
        }

        res.send({
            success: true,
            role: user.role,
        });
    } catch (error) {
        res.status(500).send({
            success: false,
            message: "❌ Server Error",
            error: error.message,
        });
    }
});
// 

// this end point is just for delete mange user of user collection

app.delete("/userDelete/:id", async (req, res) => {
    const id = req.params.id;

    try {
        const result = await userCollection.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount > 0) {
            res.send({
                success: true,
                message: "✅ User deleted successfully.",
            });
        } else {
            res.status(404).send({
                success: false,
                message: "❌ No user found with this ID.",
            });
        }
    } catch (error) {
        res.status(500).send({
            success: false,
            message: "❌ Failed to delete user.",
            error: error.message,
        });
    }
});


app.patch("/users/:id", async (req, res) => {
    const { email, role } = req.body;
    const id = req.params.id;

    try {
        const result = await userCollection.updateOne(
            {
                _id: new ObjectId(id),
                email: email, // match both id and email for extra safety
            },
            {
                $set: { role: role }
            }
        );

        res.send(result)
    } catch (error) {
        res.status(500).send({
            success: false,
            message: "❌ Failed to update user role",
            error: error.message,
        });
    }
});


// Assuming you have express and a User model (mongoose)
app.patch('/users/:id', async (req, res) => {
    const userId = req.params.id;
    const { email, role } = req.body;

    try {
        // Find user by _id and update role (and optionally email)
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { role, email }, // You can remove 'email' if you don't want to update it
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(updatedUser);
    } catch (err) {
        res.status(500).json({ message: 'Failed to update user', error: err.message });
    }
});


// this post route is for user registration data
app.post("/users", async (req, res) => {
    const newUser = req.body;
    const userEmail = newUser.email;

    try {
        // Check if user already exists
        const existingUser = await userCollection.findOne({ email: userEmail });

        if (existingUser) {
            return res.status(409).send({
                success: false,
                message: "❌ User with this email already exists!",
            });
        }

        // Insert new user
        const result = await userCollection.insertOne(newUser);

        res.send({
            success: true,
            message: "✅ User added successfully!",
            insertedId: result.insertedId,
        });
    } catch (error) {
        console.error("POST /users error:", error); // optional for debugging
        res.status(500).send({
            success: false,
            message: "❌ Server Error",
            error: error.message,
        });
    }
});




// this is a test route

app.get("/", (req, res) => {
    res.send("Hello World!");
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});