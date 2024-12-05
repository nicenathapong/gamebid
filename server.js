const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const session = require("express-session");
const app = express();

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(
    session({
        secret: "your-secret-key",
        resave: false,
        saveUninitialized: false,
    })
);

// Database paths
const DB_PATH = {
    users: "./data/users.json",
    auctions: "./data/auctions.json",
    bids: "./data/bids.json",
    payments: "./data/payments.json",
};

// Initialize JSON files
Object.values(DB_PATH).forEach((path) => {
    if (!fs.existsSync(path)) {
        fs.writeFileSync(path, "[]");
    }
});

// Database helpers
const readDB = (path) => JSON.parse(fs.readFileSync(path));
const writeDB = (path, data) =>
    fs.writeFileSync(path, JSON.stringify(data, null, 2));

const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect("/login");
    }
    next();
};

// Add this to your server.js or routes file
app.get("/", (req, res) => {
    const auctions = readDB(DB_PATH.auctions);

    const featured = auctions
        .filter((a) => a.status === "active")
        .slice(0, 6)
        .map((auction) => ({
            ...auction,
            timeLeft: getTimeLeft(auction.endTime),
        }));

    const categories = [
        {
            name: "Retro Games",
            slug: "retro",
            imageUrl:
                "https://www.pclpublications.com/wp-content/uploads/2024/01/retrogames-1024x576.jpg",
        },
        {
            name: "Limited Editions",
            slug: "limited",
            imageUrl:
                "https://lh6.googleusercontent.com/IaZnfDxnNIx8PFeM4Sn2lfvkER1WfELu0mQP6etmbd5KUazS4S5nbqwMYG4iNGGuRTIuRGeFjJyfLg2fHbg96W5QeEP6Rt5mxSYbWYduKZ6vjkbqy51HCjfgDkSwzf8RbzD1DdPdmPyHl8boGZlINeI",
        },
        {
            name: "Consoles",
            slug: "console",
            imageUrl:
                "https://cdn.mos.cms.futurecdn.net/9qPwMYepYBRomZ3ifxjzCM-1200-80.png",
        },
        {
            name: "Accessories",
            slug: "accessories",
            imageUrl:
                "https://media.licdn.com/dms/image/D4D12AQG2jMnE6VTJNA/article-cover_image-shrink_600_2000/0/1692181683749?e=2147483647&v=beta&t=ejlmpckB1OWmiJ4zcKOgt6VHWYWMc8l4xIGA5DNZ1XY",
        },
    ];

    res.render("home", {
        featured,
        categories,
        user: req.session.userId
            ? readDB(DB_PATH.users).find((u) => u.id === req.session.userId)
            : null,
    });
});

// Helper function for time calculation
function getTimeLeft(endTime) {
    const diff = new Date(endTime) - new Date();
    if (diff <= 0) return "Ended";

    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

    if (days > 0) return `${days}d ${hours}h`;
    return `${hours}h`;
}

// Auth routes
app.get("/register", (req, res) => {
    res.render("register", { user: null });
});

app.post("/register", async (req, res) => {
    const users = readDB(DB_PATH.users);
    const { username, email, password, confirmPassword } = req.body;

    if (users.find((u) => u.username === username)) {
        return res.render("register", {
            user: null,
            error: "Username already exists",
        });
    }

    if (users.find((u) => u.email === email)) {
        return res.render("register", {
            user: null,
            error: "Email already registered",
        });
    }

    if (password !== confirmPassword) {
        return res.render("register", {
            user: null,
            error: "Passwords do not match",
        });
    }

    const newUser = {
        id: `user${Date.now()}`,
        username,
        email,
        password: await bcrypt.hash(password, 10),
        role: "user",
        createdAt: new Date().toISOString(),
        totalSales: 0,
        totalBids: 0,
    };

    users.push(newUser);
    writeDB(DB_PATH.users, users);

    req.session.userId = newUser.id;
    res.redirect("/");
});

app.get("/login", (req, res) => {
    res.render("login", { user: null });
});

app.post("/login", async (req, res) => {
    const users = readDB(DB_PATH.users);
    const { username, password } = req.body;
    const user = users.find((u) => u.username === username);

    if (user && (await bcrypt.compare(password, user.password))) {
        req.session.userId = user.id;
        res.redirect("/");
    } else {
        res.render("login", {
            user: null,
            error: "Invalid credentials",
        });
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

// Add POST method alternative
app.post("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get("/my-bids", requireAuth, (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const bids = readDB(DB_PATH.bids);

    const userBids = bids
        .filter((bid) => bid.userId === req.session.userId)
        .map((bid) => ({
            ...bid,
            auction: auctions.find((a) => a.id === bid.auctionId),
            timeLeft: getTimeLeft(
                auctions.find((a) => a.id === bid.auctionId)?.endTime
            ),
        }))
        .filter((bid) => bid.auction) // Remove bids for deleted auctions
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.render("my-bids", {
        user: readDB(DB_PATH.users).find((u) => u.id === req.session.userId),
        userBids,
    });
});

app.get("/category/:slug", (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const bids = readDB(DB_PATH.bids);
    const { slug } = req.params;

    const filteredAuctions = auctions
        .filter((a) => a.status === "active" && a.category === slug)
        .map((auction) => ({
            ...auction,
            totalBids: bids.filter((b) => b.auctionId === auction.id).length,
            timeLeft: getTimeLeft(auction.endTime),
        }));

    const categoryMap = {
        retro: "Retro Games",
        limited: "Limited Editions",
        console: "Consoles",
        accessories: "Accessories",
    };

    res.render("category", {
        auctions: filteredAuctions,
        category: categoryMap[slug],
        user: req.session.userId
            ? readDB(DB_PATH.users).find((u) => u.id === req.session.userId)
            : null,
    });
});

app.get("/auctions", (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const bids = readDB(DB_PATH.bids);
    const { search, category, sort } = req.query;

    let filteredAuctions = auctions.filter((a) => a.status === "active");

    // Search filter
    if (search) {
        const searchLower = search.toLowerCase();
        filteredAuctions = filteredAuctions.filter(
            (auction) =>
                auction.title.toLowerCase().includes(searchLower) ||
                auction.description.toLowerCase().includes(searchLower)
        );
    }

    // Category filter
    if (category && category !== "all") {
        filteredAuctions = filteredAuctions.filter(
            (a) => a.category === category
        );
    }

    // Sort
    switch (sort) {
        case "ending":
            filteredAuctions.sort(
                (a, b) => new Date(a.endTime) - new Date(b.endTime)
            );
            break;
        case "new":
            filteredAuctions.sort(
                (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
            );
            break;
        case "price-low":
            filteredAuctions.sort((a, b) => a.currentPrice - b.currentPrice);
            break;
        case "price-high":
            filteredAuctions.sort((a, b) => b.currentPrice - a.currentPrice);
            break;
    }

    const enrichedAuctions = filteredAuctions.map((auction) => ({
        ...auction,
        totalBids: bids.filter((b) => b.auctionId === auction.id).length,
        timeLeft: getTimeLeft(auction.endTime),
    }));

    res.render("auctions", {
        user: req.session.userId
            ? readDB(DB_PATH.users).find((u) => u.id === req.session.userId)
            : null,
        auctions: enrichedAuctions,
        search,
        category,
        sort,
    });
});
// Auction routes
app.get("/auctions/new", requireAuth, (req, res) => {
    res.render("new-auction");
});

app.get("/sell", requireAuth, (req, res) => {
    res.render("sell", {
        user: readDB(DB_PATH.users).find((u) => u.id === req.session.userId),
    });
});

app.post("/auctions", requireAuth, (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const { title, description, category, condition, startingPrice, endTime } =
        req.body;

    const newAuction = {
        id: Date.now().toString(),
        sellerId: req.session.userId,
        title,
        description,
        category,
        condition,
        startingPrice: parseFloat(startingPrice),
        currentPrice: parseFloat(startingPrice),
        imageUrl: "/api/placeholder/400/400",
        endTime: new Date(endTime).toISOString(),
        status: "active",
        createdAt: new Date().toISOString(),
    };

    auctions.push(newAuction);
    writeDB(DB_PATH.auctions, auctions);
    res.redirect(`/auctions/${newAuction.id}`);
});

app.post("/auctions/:id/bid", requireAuth, (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const bids = readDB(DB_PATH.bids);
    const { id } = req.params;
    const { amount } = req.body;

    const auction = auctions.find((a) => a.id === id);
    if (
        !auction ||
        auction.status !== "active" ||
        new Date(auction.endTime) < new Date()
    ) {
        return res.status(400).send("Invalid auction");
    }

    if (parseFloat(amount) <= auction.currentPrice) {
        return res.status(400).send("Bid must be higher than current price");
    }

    const newBid = {
        id: Date.now().toString(),
        auctionId: id,
        userId: req.session.userId,
        amount: parseFloat(amount),
        timestamp: new Date().toISOString(),
    };

    auction.currentPrice = parseFloat(amount);
    bids.push(newBid);

    writeDB(DB_PATH.auctions, auctions);
    writeDB(DB_PATH.bids, bids);
    res.redirect(`/auctions/${id}`);
});

app.get("/auctions/:id", (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const bids = readDB(DB_PATH.bids);
    const users = readDB(DB_PATH.users);

    const auction = auctions.find((a) => a.id === req.params.id);
    if (!auction) {
        return res.status(404).render("404");
    }

    const auctionBids = bids
        .filter((b) => b.auctionId === auction.id)
        .map((b) => ({
            ...b,
            username: users.find((u) => u.id === b.userId)?.username,
        }))
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Calculate time left
    const timeLeft = getTimeLeft(auction.endTime);

    res.render("auction-detail", {
        auction,
        bids: auctionBids,
        timeLeft,
        user: req.session.userId
            ? users.find((u) => u.id === req.session.userId)
            : null,
    });
});

function getTimeLeft(endTime) {
    const diff = new Date(endTime) - new Date();
    if (diff <= 0) return "Ended";

    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

    return `${days}d ${hours}h ${minutes}m`;
}

app.get("/categories", (req, res) => {
    const auctions = readDB(DB_PATH.auctions);

    const categories = [
        {
            name: "Retro Games",
            slug: "retro",
            imageUrl:
                "https://www.pclpublications.com/wp-content/uploads/2024/01/retrogames-1024x576.jpg",
            count: auctions.filter((a) => a.category === "retro").length,
        },
        {
            name: "Limited Editions",
            slug: "limited",
            imageUrl:
                "https://lh6.googleusercontent.com/IaZnfDxnNIx8PFeM4Sn2lfvkER1WfELu0mQP6etmbd5KUazS4S5nbqwMYG4iNGGuRTIuRGeFjJyfLg2fHbg96W5QeEP6Rt5mxSYbWYduKZ6vjkbqy51HCjfgDkSwzf8RbzD1DdPdmPyHl8boGZlINeI",
            count: auctions.filter((a) => a.category === "limited").length,
        },
        {
            name: "Consoles",
            slug: "console",
            imageUrl:
                "https://cdn.mos.cms.futurecdn.net/9qPwMYepYBRomZ3ifxjzCM-1200-80.png",
            count: auctions.filter((a) => a.category === "console").length,
        },
        {
            name: "Accessories",
            slug: "accessories",
            imageUrl:
                "https://media.licdn.com/dms/image/D4D12AQG2jMnE6VTJNA/article-cover_image-shrink_600_2000/0/1692181683749?e=2147483647&v=beta&t=ejlmpckB1OWmiJ4zcKOgt6VHWYWMc8l4xIGA5DNZ1XY",
            count: auctions.filter((a) => a.category === "accessories").length,
        },
    ];

    res.render("categories", {
        categories,
        user: req.session.userId
            ? readDB(DB_PATH.users).find((u) => u.id === req.session.userId)
            : null,
    });
});

app.get("/profile", requireAuth, (req, res) => {
    const users = readDB(DB_PATH.users);
    const auctions = readDB(DB_PATH.auctions);
    const bids = readDB(DB_PATH.bids);

    const user = users.find((u) => u.id === req.session.userId);
    const userBids = bids.filter((b) => b.userId === user.id);

    // Fetch active bids with auction details
    const activeBids = userBids
        .map((bid) => ({
            ...bid,
            auction: auctions.find((a) => a.id === bid.auctionId),
        }))
        .filter((bid) => bid.auction && bid.auction.status === "active")
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Fetch won items
    const wonItems = auctions.filter(
        (a) => a.status === "completed" && a.winnerId === user.id
    );

    // Fetch user's listings
    const listings = auctions
        .filter((a) => a.sellerId === user.id)
        .map((listing) => ({
            ...listing,
            totalBids: bids.filter((b) => b.auctionId === listing.id).length,
        }));

    // Calculate user stats
    const userStats = {
        totalBids: userBids.length,
        wonAuctions: wonItems.length,
        totalSales: listings.filter((l) => l.status === "completed").length,
    };

    res.render("profile", {
        user,
        userStats,
        activeBids,
        wonItems,
        listings,
    });
});

app.get("/admin/login", (req, res) => {
    res.render("admin/login", { user: null });
});

app.post("/admin/login", async (req, res) => {
    const users = readDB(DB_PATH.users);
    const { username, password } = req.body;
    const user = users.find(
        (u) => u.username === username && u.role === "admin"
    );

    if (user && (await bcrypt.compare(password, user.password))) {
        req.session.userId = user.id;
        req.session.isAdmin = true;
        res.redirect("/admin");
    } else {
        res.render("admin/login", {
            user: null,
            error: "Invalid admin credentials",
        });
    }
});

// Middleware for admin routes
const requireAdmin = (req, res, next) => {
    if (!req.session.isAdmin) {
        return res.redirect("/admin/login");
    }
    next();
};

app.get("/admin", requireAdmin, (req, res) => {
    const users = readDB(DB_PATH.users);
    const auctions = readDB(DB_PATH.auctions);
    const bids = readDB(DB_PATH.bids);

    const stats = {
        totalUsers: users.length,
        activeAuctions: auctions.filter((a) => a.status === "active").length,
        totalBids: bids.length,
    };

    const recentUsers = users
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice(0, 5)
        .map((user) => ({
            ...user,
            totalBids: bids.filter((b) => b.userId === user.id).length,
        }));

    const recentAuctions = auctions
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice(0, 5)
        .map((auction) => ({
            ...auction,
            totalBids: bids.filter((b) => b.auctionId === auction.id).length,
        }));

    res.render("admin/dashboard", {
        user: users.find((u) => u.id === req.session.userId),
        stats,
        recentUsers,
        recentAuctions,
    });
});

app.get("/admin/users", requireAdmin, (req, res) => {
    const users = readDB(DB_PATH.users);
    res.render("admin/users", {
        user: users.find((u) => u.id === req.session.userId),
        users: users.sort(
            (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
        ),
    });
});

app.post("/admin/users", requireAdmin, async (req, res) => {
    const users = readDB(DB_PATH.users);
    const { username, email, password, role } = req.body;

    const newUser = {
        id: `user${Date.now()}`,
        username,
        email,
        password: await bcrypt.hash(password, 10),
        role: role || "user",
        createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    writeDB(DB_PATH.users, users);
    res.redirect("/admin/users");
});

app.post("/admin/users/:id", requireAdmin, async (req, res) => {
    const users = readDB(DB_PATH.users);
    const { username, email, password, role } = req.body;
    const userIndex = users.findIndex((u) => u.id === req.params.id);

    if (userIndex === -1) return res.redirect("/admin/users");

    const updatedUser = { ...users[userIndex] };
    updatedUser.username = username;
    updatedUser.email = email;
    if (password) {
        updatedUser.password = await bcrypt.hash(password, 10);
    }
    if (role && (req.session.userId !== req.params.id || role === "admin")) {
        updatedUser.role = role;
    }

    users[userIndex] = updatedUser;
    writeDB(DB_PATH.users, users);
    res.redirect("/admin/users");
});

app.delete("/admin/users/:id", requireAdmin, (req, res) => {
    const users = readDB(DB_PATH.users);
    const userIndex = users.findIndex((u) => u.id === req.params.id);

    if (userIndex === -1)
        return res.status(404).json({ error: "User not found" });
    if (users[userIndex].role === "admin")
        return res.status(403).json({ error: "Cannot delete admin" });

    users.splice(userIndex, 1);
    writeDB(DB_PATH.users, users);
    res.json({ success: true });
});

// Admin APIs - User Management
app.get("/api/admin/users", requireAdmin, (req, res) => {
    const users = readDB(DB_PATH.users);
    res.json(users.map(({ password, ...user }) => user));
});

app.post("/api/admin/users", requireAdmin, async (req, res) => {
    const users = readDB(DB_PATH.users);
    const { username, password, role } = req.body;

    if (users.find((u) => u.username === username)) {
        return res.status(400).json({ error: "Username already exists" });
    }

    const newUser = {
        id: Date.now().toString(),
        username,
        password: await bcrypt.hash(password, 10),
        role: role || "user",
        createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    writeDB(DB_PATH.users, users);
    res.status(201).json({ id: newUser.id, username, role });
});

app.put("/api/admin/users/:id", requireAdmin, async (req, res) => {
    const users = readDB(DB_PATH.users);
    const { username, password, role } = req.body;
    const userIndex = users.findIndex((u) => u.id === req.params.id);

    if (userIndex === -1)
        return res.status(404).json({ error: "User not found" });

    const updatedUser = { ...users[userIndex] };
    if (username) updatedUser.username = username;
    if (password) updatedUser.password = await bcrypt.hash(password, 10);
    if (role) updatedUser.role = role;

    users[userIndex] = updatedUser;
    writeDB(DB_PATH.users, users);
    res.json({ message: "User updated successfully" });
});

app.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
    const users = readDB(DB_PATH.users);
    const userIndex = users.findIndex((u) => u.id === req.params.id);

    if (userIndex === -1)
        return res.status(404).json({ error: "User not found" });

    users.splice(userIndex, 1);
    writeDB(DB_PATH.users, users);
    res.json({ message: "User deleted successfully" });
});

// Admin APIs - Auction Management
app.get("/admin/auctions", requireAdmin, (req, res) => {
    const { status, category, search } = req.query;
    let auctions = readDB(DB_PATH.auctions);

    if (status && status !== "all") {
        auctions = auctions.filter((a) => a.status === status);
    }
    if (category && category !== "all") {
        auctions = auctions.filter((a) => a.category === category);
    }
    if (search) {
        auctions = auctions.filter(
            (a) =>
                a.title.toLowerCase().includes(search.toLowerCase()) ||
                a.description.toLowerCase().includes(search.toLowerCase())
        );
    }

    res.render("admin/auctions", {
        user: readDB(DB_PATH.users).find((u) => u.id === req.session.userId),
        auctions: auctions.sort(
            (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
        ),
    });
});

app.delete("/admin/auctions/:id", requireAdmin, (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const auctionIndex = auctions.findIndex((a) => a.id === req.params.id);

    if (auctionIndex === -1)
        return res.status(404).json({ error: "Auction not found" });

    auctions.splice(auctionIndex, 1);
    writeDB(DB_PATH.auctions, auctions);
    res.json({ success: true });
});
// Add these routes to server.js
app.post("/admin/auctions", requireAdmin, (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const { title, description, category, startingPrice, endTime, status } =
        req.body;

    const newAuction = {
        id: Date.now().toString(),
        title,
        description,
        category,
        startingPrice: parseFloat(startingPrice),
        currentPrice: parseFloat(startingPrice),
        endTime: new Date(endTime).toISOString(),
        status,
        createdAt: new Date().toISOString(),
        createdBy: req.session.userId,
        imageUrl: "/api/placeholder/400/400",
    };

    auctions.push(newAuction);
    writeDB(DB_PATH.auctions, auctions);
    res.redirect("/admin/auctions");
});

app.get("/admin/auctions/:id/data", requireAdmin, (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const auction = auctions.find((a) => a.id === req.params.id);
    if (!auction) return res.status(404).json({ error: "Auction not found" });
    res.json(auction);
});

app.post("/admin/auctions/:id", requireAdmin, (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const { title, description, category, startingPrice, endTime, status } =
        req.body;
    const auctionIndex = auctions.findIndex((a) => a.id === req.params.id);

    if (auctionIndex === -1) return res.redirect("/admin/auctions");

    auctions[auctionIndex] = {
        ...auctions[auctionIndex],
        title,
        description,
        category,
        startingPrice: parseFloat(startingPrice),
        endTime: new Date(endTime).toISOString(),
        status,
        updatedAt: new Date().toISOString(),
    };

    writeDB(DB_PATH.auctions, auctions);
    res.redirect("/admin/auctions");
});

// Admin APIs - Reports
app.get("/api/admin/reports/sales", requireAdmin, (req, res) => {
    const auctions = readDB(DB_PATH.auctions);
    const bids = readDB(DB_PATH.bids);
    const payments = readDB(DB_PATH.payments);

    const report = {
        totalAuctions: auctions.length,
        activeAuctions: auctions.filter((a) => a.status === "active").length,
        completedAuctions: auctions.filter((a) => a.status === "completed")
            .length,
        totalBids: bids.length,
        totalRevenue: payments.reduce((sum, p) => sum + p.amount, 0),
        averageBidsPerAuction: bids.length / auctions.length || 0,
    };

    res.json(report);
});

app.get("/api/admin/reports/users", requireAdmin, (req, res) => {
    const users = readDB(DB_PATH.users);
    const bids = readDB(DB_PATH.bids);
    const auctions = readDB(DB_PATH.auctions);

    const userStats = users.map((user) => ({
        id: user.id,
        username: user.username,
        role: user.role,
        totalBids: bids.filter((b) => b.userId === user.id).length,
        totalAuctions: auctions.filter((a) => a.sellerId === user.id).length,
        winningBids: bids.filter((b) => {
            const auction = auctions.find((a) => a.id === b.auctionId);
            return (
                auction &&
                auction.status === "completed" &&
                auction.winnerId === user.id
            );
        }).length,
    }));

    res.json(userStats);
});

// Admin APIs - Payment Management
app.get("/api/admin/payments", requireAdmin, (req, res) => {
    const payments = readDB(DB_PATH.payments);
    res.json(payments);
});

app.post("/api/admin/payments/verify/:id", requireAdmin, (req, res) => {
    const payments = readDB(DB_PATH.payments);
    const payment = payments.find((p) => p.id === req.params.id);

    if (!payment) return res.status(404).json({ error: "Payment not found" });

    payment.status = "verified";
    payment.verifiedAt = new Date().toISOString();
    payment.verifiedBy = req.session.userId;

    writeDB(DB_PATH.payments, payments);
    res.json(payment);
});

app.get("/api/admin/payments/pending", requireAdmin, (req, res) => {
    const payments = readDB(DB_PATH.payments);
    const pendingPayments = payments.filter((p) => p.status === "pending");
    res.json(pendingPayments);
});

app.get("/about", (req, res) => {
    res.render("about", {
        user: req.session.userId
            ? readDB(DB_PATH.users).find((u) => u.id === req.session.userId)
            : null,
    });
});

app.get("/help", (req, res) => {
    res.render("help", {
        user: req.session.userId
            ? readDB(DB_PATH.users).find((u) => u.id === req.session.userId)
            : null,
    });
});

app.get("/terms", (req, res) => {
    res.render("terms", {
        user: req.session.userId
            ? readDB(DB_PATH.users).find((u) => u.id === req.session.userId)
            : null,
    });
});

app.get("/privacy", (req, res) => {
    res.render("privacy", {
        user: req.session.userId
            ? readDB(DB_PATH.users).find((u) => u.id === req.session.userId)
            : null,
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
