// TradeSchoolBarGraph.jsx
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts';

// Assume props.data is your US Census data as an array
const TradeSchoolBarGraph = ({ data }) => (
  <BarChart width={600} height={300} data={data}>
    <XAxis dataKey="State" />
    <YAxis />
    <Tooltip />
    <Legend />
    <Bar dataKey="Employment" fill="#8884d8" />
  </BarChart>
);
export default TradeSchoolBarGraph;
