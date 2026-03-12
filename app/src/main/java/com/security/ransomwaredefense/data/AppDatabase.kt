package com.security.ransomwaredefense.data

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface ThreatLogDao {
    @Insert
    suspend fun insert(log: ThreatLog)

    @Query("SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT 100")
    fun getAllLogs(): Flow<List<ThreatLog>>

    @Query("DELETE FROM threat_logs")
    suspend fun clearAll()
}

@Dao
interface BehaviorHistoryDao {
    @Insert
    suspend fun insert(history: BehaviorHistory)

    @Query("SELECT * FROM behavior_history ORDER BY timestamp DESC LIMIT 50")
    fun getHistory(): Flow<List<BehaviorHistory>>
}

@Database(entities = [ThreatLog::class, BehaviorHistory::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun threatLogDao(): ThreatLogDao
    abstract fun behaviorHistoryDao(): BehaviorHistoryDao

    companion object {
        @Volatile private var INSTANCE: AppDatabase? = null

        fun getInstance(context: android.content.Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                Room.databaseBuilder(context, AppDatabase::class.java, "ransomware_defense_db")
                    .build().also { INSTANCE = it }
            }
        }
    }
}